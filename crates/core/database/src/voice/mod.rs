use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock,
    },
};

use crate::{
    events::client::EventV1,
    models::{Channel, User},
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, Server, MAX_MLS_GROUP_MEMBERS,
};
use iso8601_timestamp::{Duration, Timestamp};
use livekit_protocol::{ParticipantInfo, ParticipantPermission, TrackSource};
use redis_kiss::{
    get_connection as _get_connection,
    redis::{
        ErrorKind, FromRedisValue, Pipeline, RedisError, RedisWrite, Script, ToRedisArgs, Value,
    },
    AsyncCommands, Conn,
};
use revolt_config::{config, FeaturesLimits};
use revolt_models::v0::{self, PartialUserVoiceState, UserVoiceState};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result, ToRevoltError};

pub mod afk_idle;
pub mod annotations;
pub mod remote_control;
pub mod watch;
mod voice_client;
pub use voice_client::{
    screen_leg_participant_permissions, EvictionFailure, VoiceClient, MOVE_TOKEN_TTL,
    SFU_BREAKER_WINDOW, SFU_CALL_TIMEOUT,
};

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

/// Whether a LiveKit `TrackSource` int is SCREENSHARE VIDEO specifically
/// (source 3) — as opposed to a camera, which is the other video source.
///
/// The distinction matters for limit enforcement: a camera's aspect ratio is
/// a property of the capture device and a strange one is a bypass attempt,
/// whereas a screenshare's is simply whatever the user's monitor or window
/// is. See the aspect-ratio branch in voice-ingress `api.rs`.
pub fn is_screenshare_video(source: i32) -> bool {
    source == 3
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
/// participant's full identity here (a hash per channel) so a server-side
/// operation acting on ONE connection of a user (the remote-control accept,
/// the Android screen leg, captions and annotations) can name the identity
/// the SFU actually knows. User ids are ULIDs and never contain `:`, so the
/// user id is always the segment before the first `:`.
///
/// 🔴 The map is keyed per USER, not per connection, and the premise that used
/// to be written here — that the MLS delivery service's one-device-per-user
/// rule (plan §1.5) makes that lossless — DOES NOT HOLD. The MLS rule binds
/// only ENROLLED seats, and LiveKit evicts only on a DUPLICATE identity, so
/// `{user}` and `{user}:{device}` coexist happily in one room. Two sessions get
/// in because `raise_if_in_voice` tests `vc:{user}`, a set written by
/// voice-ingress from a webhook rather than by the join route, so two joins
/// inside the round-trip window both read it empty. The HSET below is then
/// last-writer-wins, decided by webhook ordering.
///
/// So a lookup here answers "ONE identity this user was last seen under in this
/// channel", never "the identities this user holds". Anything that has to be
/// correct for an account sitting in a room twice asks the SFU for its
/// participant list instead: the voice move through
/// `VoiceClient::list_participants_if_present` (see `select_move_connection`
/// and `eviction_targets`), the moderation removals (kick, ban, leave,
/// disconnect, force-disconnect) through
/// `VoiceClient::remove_user_if_present_sids`, and the permission syncs
/// through `VoiceClient::list_participants_reported` (AFK S-3 D-2, D-4). No
/// removal and no permission push resolves through this map any more; the
/// methods that did (`remove_user`, `mute_track`,
/// `update_permissions_if_present`) were deleted in the S-3 cleanup.
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
    let stored = stored_voice_participant_identity(channel_id, user_id).await?;

    Ok(stored.unwrap_or_else(|| {
        // No recorded identity: fall back to the bare user id. This is
        // correct for non-E2EE participants (their SFU identity IS the bare
        // user id), but for a device-qualified participant whose mapping was
        // evicted/never-written it means an operation addressed by it (the
        // callers named on `user_id_from_participant_identity`) will match no
        // SFU participant and silently no-op — surface it (plan §1.5, 6.4
        // roster reconciliation).
        log::debug!(
            "voice identity mapping missing for {user_id} in {channel_id}; using bare user id (moderation of a device-qualified participant may not apply)"
        );
        user_id.to_string()
    }))
}

/// The identity mapping EXACTLY as recorded: `None` when no mapping exists,
/// with none of `get_voice_participant_identity`'s bare-id fallback.
///
/// The voice move needs the difference. It treats the mapping as a
/// preference among the connections the SFU actually lists, and a fallback
/// bare id would read as "the mapping names the bare seat" when it names
/// nothing at all — steering the choice toward a bare connection for no
/// reason, and hiding the "mapping absent" case from its log.
async fn stored_voice_participant_identity(
    channel_id: &str,
    user_id: &str,
) -> Result<Option<String>> {
    get_connection()
        .await?
        .hget(format!("voice_identity:{channel_id}"), user_id)
        .await
        .to_internal_error()
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

/// The session that owns a user's participant in a call: HASH
/// `voice_session:{channel_id}`, field `user_id` -> `session_id`. A move event
/// goes to this session and nowhere else, so one session of a user can never
/// make ANOTHER session (one it just kicked with `force_disconnect`, say)
/// rejoin somewhere.
///
/// Lifecycle:
/// - `join_call` writes it for every join, bare or device-qualified, once
///   nothing else can refuse the join. A moderator move carries the source
///   channel's session over to the destination
///   ([`carry_voice_participant_session`]), because the moved client may join
///   with the pre-minted token and never call `join_call`.
/// - A leave does not drop a user's record: livekit's full reconnect
///   (`restartConnection`, a network switch) rejoins with the same token and
///   never calls `join_call`, so a record dropped on its `participant_left`
///   would be gone for the rejoin, and the next move would reach nobody. A
///   record left behind is harmless: a move reads it only while the user has
///   voice state in that channel, and every way back in (`join_call`, whose
///   `force_disconnect` / `raise_if_in_voice` also clear or refuse any voice
///   state first, or a move) writes it again.
/// - Two paths drop a single user's record, both kicks and both BEFORE
///   their removal ([`drop_voice_participant_session`]): `join_call`'s
///   `force_disconnect` kick, for every channel it kicks the user out of
///   (it may land in another channel than the one it records), and the
///   disconnect in `member_edit` (`remove: ["VoiceChannel"]`, a moderator's
///   or a self-disconnect from any session of the user), for the gated
///   source (media-e2ee S6M-2). A kick is not a reconnect.
/// - [`delete_channel_voice_state`] drops the whole hash with the call, and
///   the reconcile sweep with a dead room.
///
/// A disconnect does not leave the record behind (media-e2ee S6M-2): a move
/// in flight out of the channel fails its re-check instead of handing the
/// evicted session a token, but only if the drop lands BEFORE that re-check
/// reads the record. A drop that lands after it, in the move's window from
/// the re-check to the publish (Redis writes only: the admission key and the
/// marker), is not seen, and the move is still announced to the session the
/// disconnect evicts. That window is the accepted residual (merge slice
/// SEC2-7's class), the same one a `join_call` kick has.
///
/// A disconnect whose drop fails is refused with the record intact. One
/// whose drop succeeds and whose eviction then fails leaves the target
/// connected with NO record until they rejoin through `join_call`
/// (media-e2ee S6R-3):
/// - a moderator's move of them is done as a disconnect
///   (`VoiceMoveOutcome::Disconnected`);
/// - a self-move is refused `NotAuthenticated` (401), a 401 that is not a
///   sign-out (Phase FE);
/// - the AFK sweep skips them;
/// - the idle beacon (`afk_idle`) answers 403 `NotOwner`, which the client
///   may latch on until it rejoins.
///
/// The same state can follow a same-channel `join_call` racing a moderator's
/// disconnect: the join records its NEW session, the disconnect's drop then
/// removes that record, and a connection the disconnect did not evict stays
/// connected with no record (the sweep, the self-move and the beacon are
/// dead for it until it rejoins). All of that is the safe direction: nobody
/// is handed a token. So is a session kicked or disconnected here that
/// zombie-rejoins the same channel through livekit's full reconnect (a
/// reconnect racing the removal, say): no record names it, so no move is
/// announced to it. Whether a client that does receive a move follows it is
/// the client's move decision (Phase FE).
///
/// Every eviction path except `join_call`'s kick and `member_edit`'s
/// disconnect keeps the record (media-e2ee S6RM-3, S6F3A-3; accepted): it
/// removes the participant without dropping its record first (a path that
/// deletes the call drops the whole hash only afterwards, with the call). A
/// move racing such an eviction still passes its compares and is announced
/// to the evicted owner. It is accepted because that owner is the LEGITIMATE
/// one, the session its own join admitted, never another session of the
/// user, so it is not the F1 shape, and because what the moved client can do
/// with the token is bounded by voice-ingress's membership and ViewChannel
/// re-check on its join (AFK S-3 D-3), which an ingress older than that
/// check does not make. Group calls are outside this: a move is
/// server-only.
///
/// No TTL, like every voice key: it lives as long as the call.
pub fn voice_session_key(channel_id: &str) -> String {
    format!("voice_session:{channel_id}")
}

/// The seat a session record says its session holds in the call (merge slice
/// RRB-1, the operator's ruling 2026-09-28, Option A): `join_call` records it
/// with the session, a move carries it with the session, and a move mints
/// exactly this kind of seat ([`move_event_delivery`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeatKind {
    /// Joined as its E2EE device: the LiveKit identity `{user}:{device}`.
    Device(String),
    /// Joined as the bare identity `{user}`.
    Bare,
    /// Not known: a record from before the seat kind was recorded (a value
    /// that is the session id alone), or one this build cannot read (any
    /// other suffix, an empty device id). Never minted a token for. The two
    /// part ways at the move (merge slice SEC4-3): an owner recorded in the
    /// old form is told with no token, but a record this build cannot read
    /// is never carried. The carry-over compares the stored value raw with
    /// the record rebuilt from what was parsed (the session id alone), which
    /// a malformed value never equals, so every move the owner would be told
    /// about answers `NotConnected` (unless a tokenless refusal,
    /// `TargetCannotJoin`, comes first) until the owner rejoins through
    /// `join_call`, which records a readable seat.
    Unknown,
}

/// Splits a session record into its session and its seat kind. Session ids
/// are ULIDs, so the first one in a value always ends the session.
const VOICE_SESSION_SEAT_SEPARATOR: char = '|';

/// The value a session record stores (one hash field, so the record is
/// written, compared and carried as one string):
///
/// - `{session}|d:{device}`: seated as that device;
/// - `{session}|b`: seated bare;
/// - `{session}`: seat unknown, the form every record had before the seat
///   kind was recorded.
fn voice_session_record(session_id: &str, seat: &SeatKind) -> String {
    match seat {
        SeatKind::Device(device_id) => {
            format!("{session_id}{VOICE_SESSION_SEAT_SEPARATOR}d:{device_id}")
        }
        SeatKind::Bare => format!("{session_id}{VOICE_SESSION_SEAT_SEPARATOR}b"),
        SeatKind::Unknown => session_id.to_string(),
    }
}

/// Read a stored session record ([`voice_session_record`]): the session up
/// to the first separator, then the seat kind. A value with no separator
/// (the old form), an empty device id or any other suffix is
/// [`SeatKind::Unknown`]; an empty session is no record at all.
fn parse_voice_session_record(stored: &str) -> Option<(String, SeatKind)> {
    let (session_id, seat) = match stored.split_once(VOICE_SESSION_SEAT_SEPARATOR) {
        None => (stored, SeatKind::Unknown),
        Some((session_id, "b")) => (session_id, SeatKind::Bare),
        Some((session_id, seat)) => match seat.strip_prefix("d:") {
            Some(device_id) if !device_id.is_empty() => {
                (session_id, SeatKind::Device(device_id.to_string()))
            }
            _ => (session_id, SeatKind::Unknown),
        },
    };

    (!session_id.is_empty()).then(|| (session_id.to_string(), seat))
}

/// Record the session a user is joining a call from (`join_call`), and the
/// seat it joins as: `device_id` is `Some(device)` when the join admits the
/// session as that E2EE device (the identity `{user}:{device}`), `None` when
/// it joins bare. An empty device id records the seat as unknown, never as
/// bare or as a device. A session id holding the record's separator cannot
/// be recorded (session ids are ULIDs, so this never happens) and is an
/// error, with nothing written.
pub async fn set_voice_participant_session(
    channel_id: &str,
    user_id: &str,
    session_id: &str,
    device_id: Option<&str>,
) -> Result<()> {
    if session_id.contains(VOICE_SESSION_SEAT_SEPARATOR) {
        return Err(create_error!(InternalError));
    }

    let seat = match device_id {
        None => SeatKind::Bare,
        Some(device_id) if !device_id.is_empty() => SeatKind::Device(device_id.to_string()),
        Some(_) => SeatKind::Unknown,
    };

    get_connection()
        .await?
        .hset(
            voice_session_key(channel_id),
            user_id,
            voice_session_record(session_id, &seat),
        )
        .await
        .to_internal_error()
}

/// Drop one user's session record in one channel. Exactly two callers, both
/// kicks, each BEFORE its removal (merge slice SEC2-6, amended by media-e2ee
/// S6M-2; pinned workspace-wide by
/// `a_session_record_is_dropped_only_by_a_kick_or_a_disconnect`):
/// `join_call`'s `force_disconnect` loop, for each channel it kicks the user
/// out of, and `member_edit`'s disconnect (a moderator's or a
/// self-disconnect), for the gated source.
///
/// Why only there: a leave keeps the record for livekit's reconnect (see
/// [`voice_session_key`]), but a kick is not a reconnect. The join that kicks
/// may be into ANOTHER channel, so the record it writes does not replace this
/// one, and a disconnect writes none. Left in place, the kicked channel's
/// record would still name the evicted session, and a move already in flight
/// there would pass both of its compares ([`carry_voice_participant_session`],
/// then the re-check right before the move is announced) and deliver a token
/// to the session the kick evicted. Dropped first, any compare that reads the
/// record after the drop fails and the move is refused. A drop that lands
/// after the move's re-check, in its window to the publish (Redis writes
/// only), is not seen: that move is still announced to the evicted session,
/// the accepted residual (merge slice SEC2-7's class, media-e2ee S6R-2).
pub async fn drop_voice_participant_session(channel_id: &str, user_id: &str) -> Result<()> {
    get_connection()
        .await?
        .hdel(voice_session_key(channel_id), user_id)
        .await
        .to_internal_error()
}

/// The session that owns a user's participant in a channel, and the seat it
/// was recorded as holding ([`SeatKind`]). `None` when nothing is recorded (a
/// join from before the record existed). A record with an empty session,
/// never written by a route, reads as no record. The caller must then treat
/// the owner as unknown, never fall back to every session.
pub async fn get_voice_participant_session_seat(
    channel_id: &str,
    user_id: &str,
) -> Result<Option<(String, SeatKind)>> {
    let stored: Option<String> = get_connection()
        .await?
        .hget(voice_session_key(channel_id), user_id)
        .await
        .to_internal_error()?;

    Ok(stored.as_deref().and_then(parse_voice_session_record))
}

/// The session that owns a user's participant in a channel: the SESSION part
/// of the record alone ([`get_voice_participant_session_seat`]), whatever
/// seat it was recorded with. `None` as there.
pub async fn get_voice_participant_session(
    channel_id: &str,
    user_id: &str,
) -> Result<Option<String>> {
    Ok(get_voice_participant_session_seat(channel_id, user_id)
        .await?
        .map(|(session_id, _)| session_id))
}

/// Whether the user's session record in `channel_id` still names `expected`,
/// `None` meaning no (or an empty) record, as [`get_voice_participant_session`]
/// reads it; an empty `expected` is `None` too. Only the SESSION part is
/// compared: the seat kind recorded with it plays no part, which is right
/// for a question about the session alone (whose participant it is). The
/// move's own re-check right before it is announced compares the whole
/// record instead ([`voice_participant_record_is`], merge slice SEC4-2),
/// because the token it minted is of the recorded seat kind.
///
/// A plain read and compare: nothing is written on a match. The record can
/// change right after the read, and each caller bounds that window itself.
pub async fn voice_participant_session_is(
    channel_id: &str,
    user_id: &str,
    expected: Option<&str>,
) -> Result<bool> {
    let expected = expected.filter(|session_id| !session_id.is_empty());
    Ok(get_voice_participant_session(channel_id, user_id)
        .await?
        .as_deref()
        == expected)
}

/// Whether the user's session record in `channel_id` is still EXACTLY the
/// record a move planned on: `expected` with the seat kind `seat`, the same
/// record the carry-over compared ([`carry_voice_participant_session`]).
/// `None` (or an empty `expected`) means no record at all, as
/// [`get_voice_participant_session`] reads it, and `seat` plays no part
/// then. A move checks this right before it is announced (and so before it
/// takes the participant out of the source, which AFK's move does after the
/// announcement): a join from another session since the move read the
/// record, or a rejoin of the same session as another kind of seat (merge
/// slice SEC4-2), means the participant it would announce and remove is no
/// longer the one it planned for, or the token it minted is not the kind
/// the owner now sits as.
///
/// Compared as read ([`get_voice_participant_session_seat`]): a device seat
/// and a bare seat each have exactly one stored form, so they compare
/// exactly; only an unknown seat kind has several (the old form, or one
/// this build cannot read), and an owner whose seat kind is unknown is
/// never minted a token. A session id holding the record's separator never
/// matches (a stored session never holds one).
///
/// A plain read and compare: nothing is written on a match. The record can
/// change right after the read; the move bounds that window by reading it
/// right before the announcement.
async fn voice_participant_record_is(
    channel_id: &str,
    user_id: &str,
    expected: Option<&str>,
    seat: &SeatKind,
) -> Result<bool> {
    let expected = expected.filter(|session_id| !session_id.is_empty());
    let stored = get_voice_participant_session_seat(channel_id, user_id).await?;

    Ok(match (stored, expected) {
        (None, None) => true,
        (Some((session_id, stored_seat)), Some(expected)) => {
            session_id == expected && stored_seat == *seat
        }
        _ => false,
    })
}

/// A move's carry-over: record `session_id`, seated as `seat`, as the owner
/// of the user's participant in `destination_id`, but only if the SOURCE
/// record is still exactly that record (the session AND the seat kind the
/// move read and planned its delivery on). Returns whether it was carried;
/// `false` means another session joined the source since the move read the
/// record, or the same session joined it again as another kind of seat (or
/// the record is gone), and the move must be refused.
///
/// The WHOLE record is carried (merge slice RRB-1): the destination's record
/// names the same session with the same seat kind, so the next move out of
/// the destination mints what the owner is seated as there. The seat kind is
/// compared too, not only the session, because the destination must record
/// the seat the token this move mints puts the owner in: a same-session
/// rejoin as another kind of seat since the read would otherwise carry a
/// seat kind the move did not mint for.
///
/// ONE step, atomic in Redis (merge slice SEC2-1): the compare on the source
/// and the write to the destination run in one script
/// ([`CARRY_VOICE_PARTICIPANT_SESSION_LUA`]). As two separate steps, a carry
/// that stalled between its compare and its write could land AFTER a
/// `join_call` from another session had kicked the planned session
/// (dropping the source record) and written its own record into the
/// destination, handing the destination back to the kicked session: a later
/// move out of the destination would then be delivered to it. In one script
/// the carry runs either wholly before that kick (and the join's record
/// replaces it) or wholly after (and the source no longer names the session,
/// so nothing is carried).
///
/// The source record is left as it is: the participant is still in the
/// source until the move removes it, and a move that fails later must leave
/// it readable for a retry. The record can still change right AFTER the
/// carry (a join from another session into the source, or a kick dropping
/// it, `join_call`'s `force_disconnect` or `member_edit`'s disconnect,
/// [`drop_voice_participant_session`]), which the second compare the move
/// makes right before it is announced catches.
///
/// No fallback: a server that refuses the script fails the carry with an
/// error, which is the move's first write, so nothing has been written. A
/// non-atomic fallback would reopen exactly the race this closes. Deploy
/// note: the script's SHA is new (the EVAL / ACL probe must cover it).
pub async fn carry_voice_participant_session(
    source_id: &str,
    destination_id: &str,
    user_id: &str,
    session_id: &str,
    seat: &SeatKind,
) -> Result<bool> {
    if session_id.is_empty() || session_id.contains(VOICE_SESSION_SEAT_SEPARATOR) {
        return Ok(false);
    }

    let record = voice_session_record(session_id, seat);
    let mut invocation = CARRY_VOICE_PARTICIPANT_SESSION.prepare_invoke();
    invocation
        .key(voice_session_key(source_id))
        .key(voice_session_key(destination_id))
        .arg(user_id)
        .arg(record.as_str());

    let carried = {
        let mut conn = get_connection().await?.into_inner();
        invocation.invoke_async::<_, i64>(&mut conn).await
    }
    .to_internal_error()?;

    Ok(carried == 1)
}

/// The carry-over script ([`carry_voice_participant_session`]). `KEYS[1]` is
/// the SOURCE's `voice_session:{channel}` hash, `KEYS[2]` the DESTINATION's;
/// `ARGV[1]` is the user id, `ARGV[2]` the whole record (the session and its
/// seat kind, [`voice_session_record`]). Writes the destination only while
/// the source holds exactly that (non-empty) record, so what it writes IS
/// the source's value; touches nothing else, and answers 1 when it carried,
/// 0 when not. A missing field reads as `false` in Lua, which equals no
/// string. The script text is unchanged by the seat kind (merge slice
/// RRB-1): only what the caller passes as `ARGV[2]` grew, so its hash did
/// not change either.
const CARRY_VOICE_PARTICIPANT_SESSION_LUA: &str = r"
if ARGV[2] ~= '' and redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then
  redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
  return 1
end
return 0
";

static CARRY_VOICE_PARTICIPANT_SESSION: LazyLock<Script> =
    LazyLock::new(|| Script::new(CARRY_VOICE_PARTICIPANT_SESSION_LUA));

/// The THIRD segment of a participant identity, if any — `"screen"` for a
/// screen leg (android-screen-share plan §2.2).
///
/// A leg is a second, publish-only SFU participant owned by a primary: the
/// native Android publisher, which cannot hand its MediaProjection capture to
/// the WebView's sealed WebRTC stack. `splitn(3, ..)` deliberately stops at
/// three, so a fourth segment lands inside the third and never reads as a leg.
pub fn participant_leg(identity: &str) -> Option<&str> {
    identity.splitn(3, ':').nth(2)
}

/// Whether a participant identity belongs to a screen leg. Everything
/// server-side treats a leg as a HELPER of its owner, never a member: it gets
/// no voice state, no identity mapping and no roster slot (plan §2.3).
pub fn is_screen_leg(identity: &str) -> bool {
    participant_leg(identity) == Some("screen")
}

/// The leg identity for a primary participant identity — a PURE FUNCTION of
/// the primary, so every "...and also the leg" operation can derive its target
/// without storing one.
///
/// A bare (non-device-qualified) primary gets an EMPTY device segment so the
/// result always has THREE segments: `"{primary}:screen"` on a bare `user`
/// would yield `user:screen`, which every parser reads as device = `"screen"`
/// — including `member_edit`'s `strip_prefix("{user}:")` (rev-2 review
/// §0-R.3).
pub fn screen_leg_identity(primary: &str) -> String {
    if primary.contains(':') {
        format!("{primary}:screen")
    } else {
        format!("{primary}::screen")
    }
}

/// Record a live screen leg: HASH `vc_leg:{channel_id}`, field `user_id` ->
/// the leg participant's SFU sid (voice-ingress, on leg join).
///
/// Mirrors `voice_identity:{channel_id}` and carries NO TTL — no voice key
/// has one, and a TTL'd marker would silently stop guarding a long share.
/// Cleaned by HDEL in [`delete_voice_state`] and DEL in
/// [`delete_channel_voice_state`], the two chokepoints every leave /
/// reconcile / `room_finished` path already shares.
///
/// The sid is what makes the leave leg idempotent under re-share: a leg that
/// left AFTER a newer one replaced it must not clear the new share's flags.
pub async fn record_screen_leg(channel_id: &str, user_id: &str, sid: &str) -> Result<()> {
    get_connection()
        .await?
        .hset(format!("vc_leg:{channel_id}"), user_id, sid)
        .await
        .to_internal_error()
}

/// The sid of the screen leg currently recorded for a user, if any
pub async fn get_screen_leg_sid(channel_id: &str, user_id: &str) -> Result<Option<String>> {
    get_connection()
        .await?
        .hget(format!("vc_leg:{channel_id}"), user_id)
        .await
        .to_internal_error()
}

/// Forget a user's screen-leg marker
pub async fn delete_screen_leg(channel_id: &str, user_id: &str) -> Result<()> {
    get_connection()
        .await?
        .hdel(format!("vc_leg:{channel_id}"), user_id)
        .await
        .to_internal_error()
}

/// A screen leg left the SFU (voice-ingress `participant_left`, plan §2.3).
/// Returns the voice-state delta to announce, or `None` when the event must
/// be ignored entirely.
///
/// Two guards, in this order — the order is the point:
///
/// 1. **Voice state FIRST.** If the owner has no voice state in this channel
///    the primary already left and `delete_voice_state` ran. `update_voice_state`
///    SETs `screensharing:` / `screen_video:` unconditionally, so writing here
///    would resurrect two TTL-less keys nothing will ever clean, fan a
///    spurious `UserVoiceStateUpdate` for a departed user, and fire a
///    `clear_allowed_annotators` broadcast (rev-2 review §0-R.13).
/// 2. **Then the sid.** A marker that no longer names this participant means a
///    NEWER leg replaced it (the SFU evicts the older connection on a
///    same-identity join); clearing the flags would blank the live share.
///
/// LiveKit does not reliably emit `track_unpublished` for a participant that
/// simply vanished, so this is what actually clears the "X is sharing" badge.
/// Deliberately NOT here: `delete_voice_state` (the owner is still in the
/// call) and any remote-control release (the sharer's primary is still
/// connected).
pub async fn screen_leg_left(
    channel: &UserVoiceChannel,
    user_id: &str,
    sid: &str,
) -> Result<Option<PartialUserVoiceState>> {
    if get_voice_state(channel, user_id).await?.is_none() {
        return Ok(None);
    }

    if get_screen_leg_sid(&channel.id, user_id).await?.as_deref() != Some(sid) {
        return Ok(None);
    }

    // Source 3 clears BOTH `screensharing` and `screen_video`; source 4 is the
    // screen-audio half of the same share (slice 4). Its partial is subsumed
    // by source 3's, which is what the caller announces.
    let partial = update_voice_state_tracks(channel, user_id, false, 3).await?;
    update_voice_state_tracks(channel, user_id, false, 4).await?;

    delete_screen_leg(&channel.id, user_id).await?;

    Ok(Some(partial))
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

/// Lifetime of the voice move's `moved_to` marker, in seconds. Exported so the
/// AFK sweep, whose per-member move claim must outlive the marker (Wave 5b-2
/// sweep contract), asserts that against this constant rather than against a
/// literal that could drift from it. The marker is a roster LABEL; the move's
/// admission of a target without Connect is a separate key with its own
/// lifetime ([`MOVE_ADMISSION_TTL_SECS`]).
pub const MOVED_TO_MARKER_TTL_SECS: usize = 10;

/// The voice move's ONE marker: for [`MOVED_TO_MARKER_TTL_SECS`], the target's
/// next join to `new_channel_id` is announced as a `VoiceChannelMove` from
/// `old_channel` instead of a `VoiceChannelJoin`. A label only: it admits
/// nothing (voice-ingress drains it on any join, refused or not), and the
/// voice-ingress Connect re-check honors only the move admission key
/// ([`voice_connect_still_allowed`]). Written only by a move that is
/// announced to its owning session, never by a `Nobody` disconnect. There is
/// no counterpart for the source any more: its Leave is always published
/// (Wave 5b-2 M4-b), so a move whose destination join never comes cannot
/// leave a ghost on the other clients' rosters.
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
            MOVED_TO_MARKER_TTL_SECS,
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

/// The AFK gate (AFK-channel plan D2 / audit CRITICAL-1).
///
/// Enforcement of the AFK designation is a HARD GATE applied AFTER the
/// permission calculus, never a permission denial.
/// `calculate_channel_permissions` returns `GrantAllSafe` for privileged
/// accounts and, through `calculate_server_permissions`, short-circuits for
/// the server OWNER — both before any override is read. An AFK-as-permission
/// implementation would therefore leave the owner and every staff account
/// publishing freely in the AFK channel.
///
/// The gate is carried as a VALUE rather than a `bool` parameter, and the
/// value lives in its own module so that its single field is private to that
/// module — `voice::voice_client` and `voice::remote_control` are siblings of
/// `voice::afk`, not descendants, so they cannot build `AfkGate(false)` even
/// though they live in the same crate. The only shipping constructor is
/// [`AfkGate::resolve`], which performs the lookup itself. That is the
/// structural defense against audit CRITICAL-1: a call site under compile
/// pressure has no `false` to reach for, because there is no value of any
/// argument to `resolve` that weakens the gate — passing `None` for the
/// server makes it fetch the server instead of trusting the caller.
mod afk {
    use crate::{models::Channel, Database, Server};
    use revolt_result::Result;

    /// Proof that a channel's AFK status has been resolved against its server.
    ///
    /// Deliberately NOT `Default`, NOT `From<bool>`, and with no public field:
    /// possession of one of these means the lookup happened.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct AfkGate(bool);

    impl AfkGate {
        /// Resolve whether `channel` is its server's designated AFK channel.
        ///
        /// `server` is an OPTIMIZATION, not an opt-out: when the caller
        /// already holds the right server document (the permission-sync path,
        /// which runs this once per participant) it is used directly, and
        /// otherwise — including when a caller passes a server belonging to
        /// some other server id — the document is fetched. That is what keeps
        /// `sync_voice_permissions` free of a per-participant fetch while
        /// leaving every other call site correct with `None`.
        ///
        /// Fails CLOSED by propagating: a server that cannot be read aborts
        /// the mint or the sync rather than falling through to a permissive
        /// default.
        ///
        /// The designation is honored as written even if the pointer has gone
        /// stale (the channel lost its voice information, say). A stale
        /// pointer can only ever deny publishing in a channel nobody can call
        /// in; resolving it the other way would be a bypass.
        pub async fn resolve(
            db: &Database,
            channel: &Channel,
            server: Option<&Server>,
        ) -> Result<Self> {
            // DMs, groups and saved messages have no server and therefore no
            // AFK designation.
            let Some(server_id) = channel.server() else {
                return Ok(Self(false));
            };

            let designated = match server {
                Some(server) if server.id == server_id => server.afk_channel_id.clone(),
                _ => db.fetch_server(server_id).await?.afk_channel_id,
            };

            Ok(Self(designated.as_deref() == Some(channel.id())))
        }

        /// Whether this channel's AFK designation denies ALL publishing.
        pub fn denies_publishing(self) -> bool {
            self.0
        }

        /// Test-only escape hatch so the unit tests below can exercise both
        /// sides of the gate without a database. Gated out of every shipping
        /// build by the attribute below, and the textual contract test
        /// `afk_gate_has_no_opt_out_at_any_call_site` additionally proves that
        /// no shipping source anywhere in the workspace reaches for it.
        #[cfg(test)]
        pub fn from_raw_for_tests(is_afk: bool) -> Self {
            Self(is_afk)
        }
    }
}

pub use afk::AfkGate;

pub fn get_allowed_sources(
    limits: &FeaturesLimits,
    permissions: PermissionValue,
    afk: AfkGate,
) -> Vec<TrackSource> {
    // The AFK gate (D2). Applied BEFORE anything is collected and after the
    // permission calculus has already run, so it binds the server owner and
    // privileged accounts that `calculate_channel_permissions` waves through
    // with `GrantAllSafe`.
    //
    // An empty list is the correct and only safe return: LiveKit reads an
    // empty `can_publish_sources` as "no restriction" (auth/grants.go), and
    // BOTH consumers of this slice — `voice_participant_permissions` and
    // `VoiceClient::create_token` — derive `can_publish` as
    // `!allowed_sources.is_empty()`, so the empty list can only ever ship
    // alongside `can_publish: false`. That pairing is pinned by
    // `afk_channel_yields_empty_sources_and_no_publish` for the sync and
    // remote-control sets, and on a real minted token by `voice_client.rs`'s
    // `afk_mint_tests`.
    if afk.denies_publishing() {
        return Vec::new();
    }

    let mut allowed_sources = Vec::new();

    if permissions.has(ChannelPermission::Speak as u64) {
        // `Unknown` carries the whisper track (a second audio track named
        // `whisper:<user_id>`, SFU-restricted to its target by the publisher's
        // subscription permissions). Granted alongside the microphone because
        // whispering is speaking; it deliberately maps to the no-op arm of
        // `update_voice_state_tracks` (track 0), so publishing/unpublishing a
        // whisper never flips `is_publishing` under the primary mic. Flows
        // into the live permission-sync paths automatically — they rebuild
        // from this same slice (see the lockstep note on
        // `voice_participant_permissions`).
        allowed_sources.extend([TrackSource::Microphone, TrackSource::Unknown])
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

/// Every per-call voice-state key scoped by the unique key
/// `{user_id}:{server_id | channel_id}`, as the prefix before
/// `:{unique_key}`. The ONE list the writers, the reader and both teardowns
/// must agree on: a key added to [`create_voice_state`] /
/// [`update_voice_state`] / [`get_voice_state`] must be added here AND to
/// both teardowns, which spell their keys out (the script's `KEYS[8..]` in
/// `voice_state_teardown_input`, and the DEL in
/// `delete_voice_state_unconditionally`), or it outlives the call (no voice
/// key has a TTL). `voice_state_key_list_matches_create_update_and_get` pins
/// all five against this list textually, the teardowns in this list's order.
const VOICE_STATE_KEY_PREFIXES: [&str; 9] = [
    "joined_at",
    "is_publishing",
    "is_receiving",
    "screensharing",
    "camera",
    "screen_video",
    "recording",
    "rc_capable",
    "watching",
];

/// The unique-key-scoped voice-state keys for one user, in
/// [`VOICE_STATE_KEY_PREFIXES`] order.
fn voice_state_keys(unique_key: &str) -> Vec<String> {
    VOICE_STATE_KEY_PREFIXES
        .iter()
        .map(|prefix| format!("{prefix}:{unique_key}"))
        .collect()
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
        recording: false,
        rc_capable: false,
        watching: false,
    };

    // The two roster memberships (`vc_members:{channel}`, `vc:{user}`) are
    // written LAST (AFK S-3 RA2-5). The pipeline is not a transaction, so a
    // reader can run between its commands, and the roster repair in
    // `get_channel_voice_state` tears down, whole-user, any member of
    // `vc_members` whose state it cannot read. Written first, the membership
    // exposed a half-created state to exactly that repair, which erased the
    // join (and its connection record) mid-write. Written last, a reader
    // that sees the membership also sees every key `get_voice_state` needs.
    Pipeline::new()
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
        // A fresh join never inherits a recording flag: the key is written
        // false here so a stale `recording:` left by a crashed process cannot
        // make a new participant appear to be recording.
        .set(format!("recording:{unique_key}"), voice_state.recording)
        // Same discipline for the capability claim: each join starts from
        // "not claimed" and the client re-announces, so a stale key cannot
        // mark a web session as able to receive control.
        .set(format!("rc_capable:{unique_key}"), voice_state.rc_capable)
        // And for the watch-party roster flag: a fresh join never inherits a
        // stale `watching:` claim — the client re-announces when it actually
        // attaches a session.
        .set(format!("watching:{unique_key}"), voice_state.watching)
        // And for draw consent: a fresh join never inherits an annotation
        // allowlist a crashed/stale session left behind (rev-3 review — a
        // resurrected list silently re-grants drawing on the next share).
        .del(format!("annotations_allow:{}:{}", &channel.id, user_id))
        // And for the AFK idle claim (Wave 5b-2 I-2): a claim left by the
        // previous call (it lives up to its TTL after a leave) must not carry
        // over into this one and count the old call's idle time. The sweep's
        // `since >= joined_at` check is the second guard. Keyed per server
        // like the flags above; the key is not in the teardown script, so
        // this DEL and its TTL are its cleanup.
        .del(afk_idle::afk_since_key(
            user_id,
            channel.server_id.as_ref().unwrap_or(&channel.id),
        ))
        // LAST: see the comment above the pipeline.
        .sadd(format!("vc_members:{}", &channel.id), user_id)
        .sadd(format!("vc:{user_id}"), channel)
        .query_async::<_, ()>(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()?;

    Ok(voice_state)
}

/// Lua source of [`DELETE_VOICE_STATE`]: the WHOLE of one user's voice-state
/// teardown in one channel, as one atomic step — or, in the per-connection
/// mode, the decision whether this departure tears anything down at all.
///
/// Argument layout. [`voice_state_teardown_input`] builds it (whole-user
/// mode) and [`voice_connection_teardown_input`] derives the per-connection
/// form from it; nothing else does, so they change together or not at all
/// (all are pinned by value in the tests):
///
/// - `KEYS[1]`: the per-server pointer `{user}:{parent}`. Its value is the id
///   of the channel the user's per-server state belongs to.
/// - `KEYS[2]`: `vc_members:{channel}`, a set of user ids.
/// - `KEYS[3]`: `vc:{user}`, the user's set of `UserVoiceChannel` strings.
/// - `KEYS[4]`: `vc_leg:{channel}`, a hash keyed by user id.
/// - `KEYS[5]`: `voice_identity:{channel}`, a hash keyed by user id.
/// - `KEYS[6]`: `annotations_allow:{channel}:{user}`, deleted whole.
/// - `KEYS[7]`: `vc_conns:{channel}`, the connection record: a hash of
///   LiveKit participant sid -> full identity, shared by EVERY user of the
///   channel (see [`voice_connections_key`]). Never deleted whole here.
/// - `KEYS[8..]`: the nine per-server flags keyed by the pointer
///   (`joined_at:`, `is_publishing:`, `is_receiving:`, `screensharing:`,
///   `camera:`, `screen_video:`, `recording:`, `rc_capable:`, `watching:`).
/// - `ARGV[1]`: the id of the channel being left, compared with the pointer.
/// - `ARGV[2]`: the user id. It is the member removed from `KEYS[2]` and the
///   field removed from `KEYS[4]` and `KEYS[5]`, and it decides which entries
///   of `KEYS[7]` are this user's: a value equal to it, or starting with it
///   and `:` (a device-qualified identity). Never a bare prefix, so user `u`
///   never owns `uu:B`.
/// - `ARGV[3]`: this channel as `vc:{user}` stores it, which is
///   `UserVoiceChannel`'s `Display`: the channel id, then `-` and the server
///   id when there is one.
/// - `ARGV[4]`: the MODE, `user`, `connection` or `connections`. Anything
///   else is an error reply with nothing touched, so a wiring slip fails
///   closed instead of silently picking a teardown.
/// - `ARGV[5]`: `connection` mode, the departing connection's sid, and
///   EXACTLY that one argument: any other ARGV count in `connection` mode is
///   an error reply with nothing touched.
/// - `ARGV[5..]`: `connections` mode (S-3 WA-R), the sids to remove, zero or
///   more, in any order. A duplicate is harmless (the second HGET finds
///   nothing).
///
/// The mode decides only what happens to `KEYS[7]` before the teardown:
///
/// - `user` (reconcile of a dead node, legacy paths with no listing, roster
///   repair): EVERY entry of this user is HDELed FIRST, and then the teardown
///   runs. There is no survivor branch in this mode at all (S-3 P2-10): a
///   whole-user removal that could answer "a sibling is still here" would
///   leave exactly the connection the caller is removing. It also erases a
///   sibling that recorded after the caller last looked at the SFU (S-3
///   WA-1), which is why every teardown that decides from an SFU listing
///   uses `connections` mode instead.
/// - `connection` (one LiveKit participant left): its sid is HDELed if its
///   recorded identity belongs to this user. A sid recorded as ANOTHER
///   user's is an error reply BEFORE any write (S-3 WA-6), not a silent
///   delete of someone else's entry. A sid with no record is a no-op. Then
///   the survivor scan: if ANOTHER entry of this user is still recorded, the
///   mapping `KEYS[5]` is re-pointed at that identity and the script returns
///   2 with NOTHING torn down. Only when none is left does the teardown run.
///   A channel with no record at all (connections that joined before the
///   record existed) finds no survivor and tears down exactly as before.
/// - `connections` (S-3 WA-R: a teardown that decided from an SFU listing):
///   each given sid is HDELed ONLY if its recorded identity belongs to this
///   user. A sid recorded as another user's is skipped and counted as
///   FOREIGN, a sid with no record is skipped and counted as UNKNOWN. Then
///   the SAME survivor scan as `connection` mode, so a sibling recorded after
///   the caller's listing keeps the state. With no sids at all it is a pure
///   survivor check: 2 when the user has any recorded entry, else the
///   teardown.
///
/// The teardown: `KEYS[2]` to `KEYS[6]` are PER-CHANNEL and always go.
/// `KEYS[1]` and `KEYS[8..]` are PER-SERVER and go UNLESS the pointer names a
/// DIFFERENT channel. A missing pointer reads as Lua `false` and falls
/// through to the delete: with no pointer there is nothing newer to protect,
/// and the flags are orphans.
///
/// Returns, in `user` and `connection` mode, an integer: 1 when the
/// per-server state was deleted, 0 when it was kept, 2 (connection mode
/// only) when a sibling connection survives and nothing was torn down. In
/// `connections` mode the same code comes back as the first element of a
/// three-integer array `{code, foreign, unknown}`, the two skip counts for
/// the caller's log line.
const DELETE_VOICE_STATE_LUA: &str = r"
local prefix = ARGV[2] .. ':'
local foreign = 0
local unknown = 0
local function answer(code)
    if ARGV[4] == 'connections' then
        return {code, foreign, unknown}
    end
    return code
end
if ARGV[4] == 'connection' and #ARGV ~= 5 then
    return redis.error_reply('ERR voice state teardown: connection mode takes one sid')
end
if ARGV[4] == 'connection' or ARGV[4] == 'connections' then
    for i = 5, #ARGV do
        local identity = redis.call('HGET', KEYS[7], ARGV[i])
        if not identity then
            unknown = unknown + 1
        elseif identity == ARGV[2] or string.sub(identity, 1, #prefix) == prefix then
            redis.call('HDEL', KEYS[7], ARGV[i])
        elseif ARGV[4] == 'connection' then
            return redis.error_reply('ERR voice state teardown: foreign connection')
        else
            foreign = foreign + 1
        end
    end
    local identities = redis.call('HVALS', KEYS[7])
    for i = 1, #identities do
        local identity = identities[i]
        if identity == ARGV[2] or string.sub(identity, 1, #prefix) == prefix then
            redis.call('HSET', KEYS[5], ARGV[2], identity)
            return answer(2)
        end
    end
elseif ARGV[4] == 'user' then
    local entries = redis.call('HGETALL', KEYS[7])
    for i = 1, #entries, 2 do
        local identity = entries[i + 1]
        if identity == ARGV[2] or string.sub(identity, 1, #prefix) == prefix then
            redis.call('HDEL', KEYS[7], entries[i])
        end
    end
else
    return redis.error_reply('ERR voice state teardown: bad mode')
end
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('SREM', KEYS[3], ARGV[3])
redis.call('HDEL', KEYS[4], ARGV[2])
redis.call('HDEL', KEYS[5], ARGV[2])
redis.call('DEL', KEYS[6])
local pointer = redis.call('GET', KEYS[1])
if pointer and pointer ~= ARGV[1] then
    return answer(0)
end
redis.call('DEL', KEYS[1], unpack(KEYS, 8))
return answer(1)
";

/// [`delete_voice_state`]'s Redis work, as one compare-and-delete script.
///
/// THE FIRST LUA SCRIPT IN THIS REPOSITORY, and here because nothing else
/// gives this check-then-act atomically. The per-server keys
/// (`{user}:{parent}` and the flags keyed by it) are shared by EVERY channel
/// of a server, so a leave from channel A that lands after the same user's
/// join to channel B would otherwise delete B's live state: a move's
/// destination `participant_joined` routinely races a sibling connection's
/// source `participant_left`, and the loser of that race used to wipe the
/// destination — an invisible publisher in B, whom the roster repair in
/// `get_channel_voice_state` then drops from `vc_members:{B}` outright.
///
/// ONE script for both halves, not a pipeline for the per-channel keys and a
/// script for the per-server ones. Two round trips left a gap between them in
/// which a same-channel re-join could write fresh per-channel state that the
/// second step then left orphaned, or a fresh pointer that the second step
/// then deleted (Wave 5b-1 audit L-6).
///
/// Why not WATCH/MULTI: WATCH is per-CONNECTION state, and connections here
/// come from a shared mobc pool. A WATCH left armed (or a MULTI half-built)
/// on a pooled connection by an error path leaks into whatever borrows that
/// connection next, and nothing in `redis_kiss` resets it. A script is
/// atomic on the server with no client-side state at all.
///
/// Every key goes in `KEYS[]`, none is built inside the script — the Redis
/// contract for scripts. That is NOT enough for Redis Cluster, and nothing
/// here makes it enough: the 16 keys carry no shared hash tag, so they span
/// hash slots, and a Cluster rejects every invocation with CROSSSLOT before
/// the script runs. [`delete_voice_state`] then takes its fallback on EVERY
/// leave, and the late-leave race this script exists to close (Wave 5b-1
/// H-1) is silently open again — the only trace is one ERROR line per
/// process. THIS SCRIPT REQUIRES A SINGLE-NODE Redis / KeyDB, which is what
/// is deployed. Under Cluster it degrades to the fallback; making it work
/// there would take hash-tagged keys across every reader and writer of them.
/// Nor is the fallback itself Cluster-safe: its one multi-key DEL spans the
/// same slots, and this module talks to Redis through a plain, non-cluster
/// connection throughout, so a Cluster deployment is unsupported by the
/// voice state layer as a whole, not by this script alone.
///
/// `Script` sends EVALSHA and loads the source on NOSCRIPT. A server that
/// provably will not run it at all is handled by [`delete_voice_state`]'s
/// fallback; see [`teardown_script_error_allows_fallback`] for what counts.
static DELETE_VOICE_STATE: LazyLock<Script> = LazyLock::new(|| Script::new(DELETE_VOICE_STATE_LUA));

/// The `KEYS[]` and `ARGV[]` of one [`DELETE_VOICE_STATE`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VoiceStateTeardownInput {
    keys: Vec<String>,
    args: Vec<String>,
}

/// Build [`DELETE_VOICE_STATE`]'s arguments in the layout documented on
/// [`DELETE_VOICE_STATE_LUA`].
///
/// Pure, so the layout is pinned by value. It has to be: a script handed the
/// wrong key or argument does not fail, it deletes nothing (or the wrong
/// thing) and returns normally.
fn voice_state_teardown_input(
    channel: &UserVoiceChannel,
    user_id: &str,
) -> VoiceStateTeardownInput {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

    VoiceStateTeardownInput {
        keys: vec![
            // KEYS[1]: the pointer. The script reads it, then deletes it with
            // the flags unless it names a different channel.
            unique_key.clone(),
            // KEYS[2] to KEYS[6]: per-channel, always deleted.
            format!("vc_members:{}", &channel.id),
            format!("vc:{user_id}"),
            // A screen leg cannot outlive the voice state it hangs off: this is
            // the chokepoint every leave / reconcile path shares, so the marker
            // dies here rather than needing its own TTL (plan §2.3).
            format!("vc_leg:{}", &channel.id),
            // Neither can the identity mapping, and for the same reason. Two of
            // the three places that used to clear it did so by calling
            // `delete_voice_participant_identity` on the line after
            // `delete_voice_state` — voice-ingress `participant_left` and the
            // reconcile sweep — which meant every OTHER caller left it
            // standing. The one that matters is `voice_join`'s
            // `force_disconnect` loop: it evicts the user from the previous
            // channel and deletes their voice state, then leaves
            // `voice_identity:{previous}` pointing at a connection that is gone
            // until an ingress webhook arrives to say so. Anything resolving an
            // identity in that window gets the stale one, which is one of the
            // two independent sources of the stale mappings that make a voice
            // move evict the wrong connection.
            //
            // Safe at every caller, because none of them needs the identity
            // after this: the reconcile sweep calls
            // `delete_voice_participant_identity` immediately after this (now
            // redundant, still harmless — HDEL is idempotent); voice-ingress
            // `participant_left` runs the connection mode, which reaches this
            // only on the user's LAST connection; the removals
            // that decide from an SFU listing (`remove_user_from_voice_channel`
            // and through it kick, ban, leave, channel and server deletion,
            // group member removal, bot deletion and the voice-ingress cap
            // backstop's `Survivor` arm; the moderator disconnect;
            // `voice_join`'s force-disconnect) address every connection by the
            // identity the SFU LISTED, never through this mapping, and they
            // reach here only in the set or connection mode, where a surviving
            // connection re-points the mapping instead of losing it; and
            // `get_channel_voice_state`'s roster repair is clearing a member
            // whose voice state is already gone. Nothing in the workspace reads
            // `get_voice_participant_identity` for a user after tearing their
            // voice state down.
            //
            // The hash can hold only ONE field per user, so clearing it on one
            // connection's departure cannot discard a mapping that some other
            // live connection of theirs was relying on — there was never
            // anywhere for a second one to live. That is the same limitation
            // the eviction leg of `move_user_to_voice_channel_expecting` and
            // `VoiceClient::remove_user_if_present_sids` exist to work around.
            format!("voice_identity:{}", &channel.id),
            // Draw consent dies with the voice state: an allowlist must not
            // outlive the call it was granted in (rev-3 review). Keyed by THIS
            // channel, so it is per-channel, not per-server.
            format!("annotations_allow:{}:{}", &channel.id, user_id),
            // KEYS[7]: the connection record. Per-channel and SHARED by every
            // user in the call, so the script only ever removes this user's
            // entries from it, never the key (S-3 D-1).
            voice_connections_key(channel),
            // KEYS[8..]: per-server, deleted with the pointer.
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            format!("screen_video:{unique_key}"),
            // Leaving the call ends any recording claim with it — this is the
            // load-bearing teardown for a recorder who drops without pressing
            // stop (a crash, a closed laptop, a network loss). Unless the user
            // is now in another channel of this server, in which case the flag
            // is THAT call's and not this one's to clear.
            format!("recording:{unique_key}"),
            format!("rc_capable:{unique_key}"),
            format!("watching:{unique_key}"),
        ],
        args: vec![
            // ARGV[1]: compared with the pointer's value.
            channel.id.clone(),
            // ARGV[2]: the member / field in KEYS[2], KEYS[4] and KEYS[5].
            user_id.to_string(),
            // ARGV[3]: the member in KEYS[3], written exactly as
            // `create_voice_state`'s `sadd` writes it.
            channel.to_string(),
            // ARGV[4]: whole-user mode. Every entry of this user leaves the
            // connection record first, and no sibling can keep the state.
            TEARDOWN_MODE_USER.to_string(),
        ],
    }
}

/// `ARGV[4]` of a whole-user [`DELETE_VOICE_STATE`] invocation.
const TEARDOWN_MODE_USER: &str = "user";

/// `ARGV[4]` of a per-connection [`DELETE_VOICE_STATE`] invocation.
const TEARDOWN_MODE_CONNECTION: &str = "connection";

/// `ARGV[4]` of a set-mode [`DELETE_VOICE_STATE`] invocation (S-3 WA-R).
const TEARDOWN_MODE_CONNECTIONS: &str = "connections";

/// What [`DELETE_VOICE_STATE`] returns in connection mode (and as the first
/// element in set mode) when another connection of the user is still
/// recorded and nothing was torn down.
const TEARDOWN_SURVIVOR: i64 = 2;

/// The DETAIL of [`DELETE_VOICE_STATE`]'s error reply when connection mode is
/// handed a sid recorded as ANOTHER user's connection (S-3 WA-6). The reply
/// comes before any write.
const TEARDOWN_FOREIGN_CONNECTION: &str = "voice state teardown: foreign connection";

/// Whether a failed [`DELETE_VOICE_STATE`] invocation is the script's own
/// WA-6 refusal: a server reply (never a transport error) whose detail names
/// a foreign connection. Only picks the log line; the caller returns an
/// error either way.
fn teardown_refused_a_foreign_connection(error: &RedisError) -> bool {
    !error.is_io_error()
        && error.kind() == ErrorKind::ResponseError
        && error
            .detail()
            .is_some_and(|detail| detail.trim().starts_with(TEARDOWN_FOREIGN_CONNECTION))
}

/// [`DELETE_VOICE_STATE`]'s arguments for ONE connection's departure: the
/// whole-user layout from [`voice_state_teardown_input`], with the mode
/// switched to `connection` and the departing sid as `ARGV[5]`.
///
/// Derived rather than written out again, so the key list cannot drift
/// between the two modes. Pure and pinned by value.
fn voice_connection_teardown_input(
    channel: &UserVoiceChannel,
    user_id: &str,
    sid: &str,
) -> VoiceStateTeardownInput {
    let mut input = voice_state_teardown_input(channel, user_id);
    input.args[3] = TEARDOWN_MODE_CONNECTION.to_string();
    input.args.push(sid.to_string());
    input
}

/// [`DELETE_VOICE_STATE`]'s arguments for a SET of connections (S-3 WA-R):
/// the whole-user layout from [`voice_state_teardown_input`], with the mode
/// switched to `connections` and the sids appended as `ARGV[5..]`, in the
/// order given. An empty `sids` leaves `ARGV` at four entries.
///
/// Derived, like [`voice_connection_teardown_input`], so the key list cannot
/// drift between the modes. Pure and pinned by value.
fn voice_connections_teardown_input(
    channel: &UserVoiceChannel,
    user_id: &str,
    sids: &[String],
) -> VoiceStateTeardownInput {
    let mut input = voice_state_teardown_input(channel, user_id);
    input.args[3] = TEARDOWN_MODE_CONNECTIONS.to_string();
    input.args.extend(sids.iter().cloned());
    input
}

/// Tear down ONE user's voice state in `channel`.
///
/// The keys it touches have two different scopes:
///
/// - PER-CHANNEL state (`vc_members:{channel}`, this channel's entry in
///   `vc:{user}`, the `vc_leg:` and `voice_identity:` fields, the
///   `annotations_allow:` list) describes membership of THIS channel only, so
///   it always goes.
/// - PER-SERVER state (the `{user}:{parent}` pointer and every flag keyed by
///   it) is shared across the server's channels, and goes only if the
///   pointer does not name a different channel.
///
/// Both halves are ONE script invocation, [`DELETE_VOICE_STATE`]; see there
/// for why it is a script and why it is one.
///
/// Outside the script, in this function:
///
/// - The watch-together session end. It publishes an event rather than
///   deleting a key, and it runs FIRST, as it always has.
/// - The FALLBACK. If the server answers the invocation with an error that
///   PROVES the script never ran — EVALSHA renamed away or ACL-denied, a
///   NOSCRIPT that survives redis-rs's own reload, a CROSSSLOT under Cluster;
///   the exact set is [`teardown_script_error_allows_fallback`] —
///   [`delete_voice_state_unconditionally`] runs instead: the teardown as it
///   was before the script existed. That brings back the late-leave race the
///   script closes (a stale leave from the source can wipe a moved user's
///   destination state), but every leave keeps working. Without it a server
///   that cannot run Lua would fail EVERY leave, and voice-ingress
///   `participant_left` would then skip its identity cleanup and its
///   `VoiceChannelLeave` event on the `?`. Such a server fails the same way
///   on every call, so the condition is logged at ERROR once per process
///   ([`TEARDOWN_FALLBACK_LOGGED`]) and at DEBUG after that. The latch
///   changes the LOGGING only: the fallback itself runs on every such call.
/// - Every OTHER error is RETURNED, with no fallback and no retry. A
///   transport error in particular (a dropped connection, a timeout) says
///   nothing about whether the script ran, and it may well have: a late
///   leave after a move returns 0 and KEEPS the destination's state, and if
///   that reply is then lost, an unconditional delete here would wipe
///   exactly what the script just decided to keep. The pre-script pipeline
///   failed on a dead connection too, so this is no regression for callers.
///
/// This is the WHOLE-USER teardown: the script runs in `user` mode, so every
/// connection of this user leaves the `vc_conns:{channel}` record first and
/// no sibling can keep the state (S-3 P2-10). One LiveKit participant leaving
/// is [`delete_voice_connection`] instead, which is what keeps a surviving
/// connection's state when only one of several leaves.
///
/// Do NOT call this after deciding from an SFU listing (moderation removal,
/// disconnect, force-disconnect, a Survivor confirmation): a sibling that
/// records AFTER the listing had its record answer "state exists" and so
/// created none of its own, and this erases the state it relies on. It is
/// left live, stateless and unrecorded (S-3 WA-1). Those callers use
/// [`delete_voice_connections`] with the sids they know about. What remains
/// here: reconcile of a dead node (no live sibling possible), legacy paths
/// with no listing, the roster repair, and the whole-call teardown.
pub async fn delete_voice_state(channel: &UserVoiceChannel, user_id: &str) -> Result<()> {
    // Watch-together dies with the HOST's voice state (plan §1): this is the
    // one chokepoint every leave path shares, and it runs BEFORE the script
    // below so the end event still reaches the departing host's own devices.
    // Per-channel — the session is keyed by this channel — so unconditional.
    watch::end_watch_session_if_host(channel, user_id).await;

    let input = voice_state_teardown_input(channel, user_id);
    let mut invocation = DELETE_VOICE_STATE.prepare_invoke();
    for key in &input.keys {
        invocation.key(key);
    }
    for arg in &input.args {
        invocation.arg(arg);
    }

    let outcome = {
        let mut conn = get_connection().await?.into_inner();
        invocation.invoke_async::<_, i64>(&mut conn).await
    };

    match outcome {
        Ok(0) => {
            log::info!(
                "voice state teardown for {user_id} in {} kept the per-server state: \
                 {} already names another channel (a late leave after a move)",
                channel.id,
                input.keys[0]
            );
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(error) if teardown_script_error_allows_fallback(&error) => {
            // Logging only: the fallback below runs whatever the latch says.
            if TEARDOWN_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                log::debug!(
                    "voice state teardown script refused for {user_id} in {}: {error}; \
                     unconditional teardown",
                    channel.id
                );
            } else {
                log::error!(
                    "voice state teardown script refused for {user_id} in {}: {error}; \
                     falling back to the unconditional teardown, which does not protect a \
                     newer channel's per-server state. This server will not run the \
                     script, so every leave takes this path; logged once per process",
                    channel.id
                );
            }
            delete_voice_state_unconditionally(channel, user_id).await
        }
        Err(error) => {
            log::warn!(
                "voice state teardown script for {user_id} in {} failed: {error}; not a \
                 refusal that proves it never ran and that the fallback could answer, so \
                 the error is returned",
                channel.id
            );
            Err(error).to_internal_error()
        }
    }
}

/// Latch for [`delete_voice_state`]'s fallback log line: ERROR the first time
/// a server refuses the script, DEBUG every time after. A server that refuses
/// it refuses it on EVERY leave, and one ERROR per leave buries everything
/// else in the log. It never gates the fallback itself.
static TEARDOWN_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

/// Whether a failed [`DELETE_VOICE_STATE`] invocation may fall back to
/// [`delete_voice_state_unconditionally`]: `true` ONLY for a server reply
/// that proves the script never ran.
///
/// The failure this guards against is the fallback UNDOING the script. A
/// late leave after a move runs the script, which returns 0 and keeps the
/// destination's per-server state; if that reply is then lost, the error
/// seen here is a transport one, and an unconditional delete would wipe
/// what the script just kept (Wave 5b-1 H-1, via audit NEW-4). So the rule
/// is an ALLOWLIST, and everything off it is returned to the caller:
///
/// - `NOSCRIPT`: redis-rs's `invoke_async` has already reloaded the source
///   and retried once (redis-rs `script.rs`), so a NOSCRIPT that reaches
///   here survived the reload. The script is not there to run.
/// - `CROSSSLOT`: a Cluster rejects the multi-slot invocation before it runs
///   (see [`DELETE_VOICE_STATE`]).
/// - `ERR unknown command ...`: EVALSHA (or the SCRIPT LOAD behind it) is
///   renamed away, which is how scripting is disabled on a stock Redis /
///   KeyDB. Checked on the reply's DETAIL, because `ErrorKind::ResponseError`
///   alone is not a server reply: redis-rs also uses that kind for a reply
///   it could not PARSE, and a garbled reply may be the script's answer.
/// - `NOPERM` naming EVALSHA or SCRIPT: an ACL refused the command itself.
///   Those are the only two commands redis-rs sends here (EVALSHA, and
///   SCRIPT LOAD on a NOSCRIPT). Any other NOPERM does not qualify. It is
///   either a key denial, which Redis checks before EVALSHA runs, or a denial
///   of a command the running script called. Either way the fallback would
///   touch the same keys with the same commands as the same user, and would
///   be refused as well.
///
/// Returned, among others: every IO error (dropped connection, timeout,
/// refusal), any other `ERR` (a Lua runtime error means the script RAN), a
/// `TypeError` (a reply arrived that was not an integer, so the script
/// ran), and every other server code (LOADING, BUSY, READONLY, MOVED, ...),
/// which the pipeline fallback would fail on just the same.
fn teardown_script_error_allows_fallback(error: &RedisError) -> bool {
    // No reply, or a torn one: the script may have run. Checked before the
    // kind, and whatever the kind says. `is_io_error` covers every transport
    // failure: redis-rs's `is_connection_dropped` and `is_timeout` only ever
    // match a subset of the same `IoError`.
    if error.is_io_error() {
        return false;
    }

    let detail = error
        .detail()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    match error.kind() {
        ErrorKind::NoScriptError | ErrorKind::CrossSlot => true,
        ErrorKind::ResponseError => detail.starts_with("unknown command"),
        ErrorKind::ExtensionError => {
            error.code() == Some("NOPERM")
                && [
                    "'evalsha' command",
                    "'script' command",
                    "'script|load' command",
                ]
                .iter()
                .any(|command| detail.contains(command))
        }
        _ => false,
    }
}

/// The FALLBACK for [`delete_voice_state`] (and, through
/// [`delete_voice_connection_unconditionally`], for a connection that turned
/// out to be the user's last), and ONLY that: the teardown exactly as it was
/// before [`DELETE_VOICE_STATE`] existed. Same keys, same commands, and every
/// per-server key deleted unconditionally.
///
/// Kept verbatim so a Redis that will not run the script degrades to the old
/// behavior rather than to a broken leave. Do not call it from anywhere else:
/// it deletes a newer channel's per-server state after a move, which is the
/// defect the script exists to fix. The reasons for each key are on
/// [`voice_state_teardown_input`].
///
/// One addition, DEGRADED like the rest of this function: every entry of
/// this user leaves the `vc_conns:{channel}` record first, as the script's
/// `user` mode does. Here it is a read and then an HDEL, not atomic with each
/// other or with the pipeline below, so a sibling recorded in between keeps
/// its entry while its voice state still goes.
///
/// DEGRADED for the connection fallbacks too (S-3 WA-2): when
/// [`delete_voice_connection_unconditionally`] or
/// [`delete_voice_connections_unconditionally`] reach this after their own
/// survivor read found none, a sibling that records between that read and
/// the pipeline below loses its state here, the WA-1 outcome the script
/// closes. The window is a few round trips wide and exists only on a server
/// that refuses the script.
async fn delete_voice_state_unconditionally(
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

    let mut conn = get_connection().await?;
    let connections: BTreeMap<String, String> = conn
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;
    let theirs: Vec<&String> = connections
        .iter()
        .filter(|(_, identity)| user_id_from_participant_identity(identity) == user_id)
        .map(|(sid, _)| sid)
        .collect();
    if !theirs.is_empty() {
        conn.hdel::<_, _, ()>(voice_connections_key(channel), theirs)
            .await
            .to_internal_error()?;
    }

    Pipeline::new()
        .srem(format!("vc_members:{}", &channel.id), user_id)
        .srem(format!("vc:{user_id}"), channel)
        .hdel(format!("vc_leg:{}", &channel.id), user_id)
        .hdel(format!("voice_identity:{}", &channel.id), user_id)
        .del(&[
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            format!("screen_video:{unique_key}"),
            format!("recording:{unique_key}"),
            format!("rc_capable:{unique_key}"),
            format!("watching:{unique_key}"),
            format!("annotations_allow:{}:{}", &channel.id, user_id),
            unique_key.clone(),
        ])
        .query_async(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()
}

// ---- the per-connection record (AFK S-3 D-1) ----
//
// Voice state is keyed per USER, but the SFU admits several connections per
// user (`{user}`, `{user}:{device}`), so a leave used to tear the user's
// state down while a sibling connection was still live: the survivor kept a
// stale grant and vanished from every roster. The record below is what lets a
// leave tell "the last connection went" from "one of several went".

/// The connection record of a channel: HASH `vc_conns:{channel_id}`, field =
/// LiveKit participant sid, value = the participant's full identity.
///
/// ONE hash per CHANNEL, shared by every user in it (S-3 P2-1):
///
/// - Per CHANNEL, not per server: a connection keeps its identity across a
///   move, so under a per-server key the late `participant_left` of a moved
///   connection in the SOURCE would find its own destination entry and read
///   it as a surviving sibling, keeping source state that must go (the H-1
///   race reborn).
/// - Per channel, not per USER: `room_finished` and the reconcile sweep call
///   [`delete_channel_voice_state`] with no user ids at all, so a per-user key
///   would be unreachable there and leak. This one is DELed with the call.
/// - Keyed by SID, not identity: a duplicate bare `{user}` reconnect is the
///   same identity with a new sid, and the OLD one's leave must not delete
///   the new one's entry.
///
/// Carries NO TTL, like every voice key. Cleaned by the per-connection HDEL
/// in [`delete_voice_connection`], the set HDEL in
/// [`delete_voice_connections`], the whole-user HDEL in
/// [`delete_voice_state`] and the DEL in [`delete_channel_voice_state`].
/// Screen legs are never recorded ([`record_voice_connection`] refuses them).
/// Deploy note: a KeyDB ACL must allow the `vc_conns:` prefix.
fn voice_connections_key(channel: &UserVoiceChannel) -> String {
    format!("vc_conns:{}", &channel.id)
}

/// Lua source of [`RECORD_VOICE_CONNECTION`]: record one connection and say
/// whether the user already holds voice state in this channel, atomically.
///
/// - `KEYS[1]`: `vc_conns:{channel}` ([`voice_connections_key`]).
/// - `KEYS[2]`: `vc_members:{channel}`.
/// - `ARGV[1]`: the connection's sid, the field.
/// - `ARGV[2]`: its full identity, the value.
/// - `ARGV[3]`: the user id, looked up in `KEYS[2]`.
///
/// Returns 1 when the user has NO voice state in this channel (the caller
/// creates it), 0 when they do (the caller refreshes the mapping hint only).
/// The answer is the voice state, NOT `HLEN == 1` (S-3 P2-1): a stale sid
/// left by a missed leave would make a real join read as a second connection
/// and never get state, and a moderator teardown racing a sibling join would
/// leave the sibling stateless for good.
const RECORD_VOICE_CONNECTION_LUA: &str = r"
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
if redis.call('SISMEMBER', KEYS[2], ARGV[3]) == 1 then
    return 0
end
return 1
";

/// A script for the same reason [`DELETE_VOICE_STATE`] is one (MULTI/WATCH
/// leak state on a pooled connection; see there), and like it a single-node
/// Redis / KeyDB script. `Script` sends EVALSHA and loads on NOSCRIPT.
static RECORD_VOICE_CONNECTION: LazyLock<Script> =
    LazyLock::new(|| Script::new(RECORD_VOICE_CONNECTION_LUA));

/// The `KEYS[]` and `ARGV[]` of one [`RECORD_VOICE_CONNECTION`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VoiceConnectionRecordInput {
    keys: Vec<String>,
    args: Vec<String>,
}

/// Build [`RECORD_VOICE_CONNECTION`]'s arguments in the layout documented on
/// [`RECORD_VOICE_CONNECTION_LUA`]. Pure, so the layout is pinned by value.
fn voice_connection_record_input(
    channel: &UserVoiceChannel,
    user_id: &str,
    sid: &str,
    identity: &str,
) -> VoiceConnectionRecordInput {
    VoiceConnectionRecordInput {
        keys: vec![
            voice_connections_key(channel),
            format!("vc_members:{}", &channel.id),
        ],
        args: vec![sid.to_string(), identity.to_string(), user_id.to_string()],
    }
}

/// Latch for [`record_voice_connection`]'s fallback log line; the same
/// once-per-process rule as [`TEARDOWN_FALLBACK_LOGGED`].
static RECORD_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);

/// Record one LiveKit connection of `user_id` in `channel` (voice-ingress,
/// `participant_joined`, after the Connect re-check).
///
/// Returns `true` when the user has NO voice state in this channel yet: the
/// caller runs the flag-resetting [`create_voice_state`] and announces the
/// join. `false` means a sibling connection already holds the state: the
/// caller refreshes the identity mapping hint only, with no flag reset (F-15)
/// and no second join event.
///
/// `identity` must be a PRIMARY of `user_id` (`{user}` or `{user}:{device}`).
/// A screen leg, or an identity of another user, is refused with an error
/// and nothing is written: a leg is a helper with no voice state (plan §2.3)
/// and a recorded one would read as a surviving sibling on its owner's leave.
///
/// If the server provably will not run the script (the
/// [`teardown_script_error_allows_fallback`] set), the same two commands run
/// as a plain pipeline instead: not atomic, which only widens the window the
/// script closes. Recording is idempotent, so that is safe to repeat.
pub async fn record_voice_connection(
    channel: &UserVoiceChannel,
    user_id: &str,
    sid: &str,
    identity: &str,
) -> Result<bool> {
    if is_screen_leg(identity) || user_id_from_participant_identity(identity) != user_id {
        log::error!(
            "refusing to record connection {sid} of {user_id} in {}: {identity} is not a \
             primary identity of that user",
            channel.id
        );
        return Err(create_error!(InternalError));
    }

    let input = voice_connection_record_input(channel, user_id, sid, identity);
    let mut invocation = RECORD_VOICE_CONNECTION.prepare_invoke();
    for key in &input.keys {
        invocation.key(key);
    }
    for arg in &input.args {
        invocation.arg(arg);
    }

    let outcome = {
        let mut conn = get_connection().await?.into_inner();
        invocation.invoke_async::<_, i64>(&mut conn).await
    };

    match outcome {
        Ok(first) => Ok(first == 1),
        Err(error) if teardown_script_error_allows_fallback(&error) => {
            if RECORD_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                log::debug!(
                    "connection record script refused for {user_id} in {}: {error}; pipeline",
                    channel.id
                );
            } else {
                log::error!(
                    "connection record script refused for {user_id} in {}: {error}; falling \
                     back to a non-atomic pipeline. This server will not run the script, so \
                     every join takes this path; logged once per process",
                    channel.id
                );
            }
            let (_, member): ((), bool) = Pipeline::new()
                .hset(&input.keys[0], sid, identity)
                .sismember(&input.keys[1], user_id)
                .query_async(&mut get_connection().await?.into_inner())
                .await
                .to_internal_error()?;
            Ok(!member)
        }
        Err(error) => Err(error).to_internal_error(),
    }
}

/// What one connection's departure amounted to, per [`delete_voice_connection`]
/// (or a set of them, per [`delete_voice_connections`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionLeave {
    /// It was the user's last recorded connection in the channel (or the
    /// channel has no record of them at all): their voice state was torn
    /// down exactly as [`delete_voice_state`] tears it down, pointer guard
    /// included. The caller announces the leave.
    Last,
    /// Another connection of the user is still recorded: NOTHING was torn
    /// down, and the identity mapping now names that connection. The caller
    /// must not announce a leave, and must not HDEL the mapping (that would
    /// undo the re-point, S-3 P2-4). The record can hold a stale sid, so
    /// voice-ingress confirms a `Survivor` against the SFU (S-3 P2-1).
    Survivor,
}

/// Another recorded connection of `user_id` than `sid`, if any, from the
/// `vc_conns:{channel}` hash as read (field = sid, value = identity).
///
/// Ownership is `user_id_from_participant_identity`, the same rule the
/// script spells as "equal, or starts with the user and `:`". Pure.
fn another_connection_of<'a>(
    connections: &'a BTreeMap<String, String>,
    user_id: &str,
    sid: &str,
) -> Option<&'a str> {
    connections
        .iter()
        .find(|(field, identity)| {
            field.as_str() != sid && user_id_from_participant_identity(identity) == user_id
        })
        .map(|(_, identity)| identity.as_str())
}

/// A recorded connection of `user_id` whose sid is NOT in `sids`, if any.
/// The set-mode twin of [`another_connection_of`], same ownership rule. Pure.
fn another_connection_outside<'a>(
    connections: &'a BTreeMap<String, String>,
    user_id: &str,
    sids: &[String],
) -> Option<&'a str> {
    connections
        .iter()
        .find(|(field, identity)| {
            !sids.contains(*field) && user_id_from_participant_identity(identity) == user_id
        })
        .map(|(_, identity)| identity.as_str())
}

/// The connections of `user_id` recorded in `channel`, as `(sid, identity)`
/// pairs from `vc_conns:{channel}`, ordered by sid (S-3 WA-R).
///
/// Ownership is `user_id_from_participant_identity`: the identity equals the
/// user id or starts with it and `:`, never a bare prefix, so user `u` never
/// owns `uu:B`. Screen legs are never recorded, so none appear. Read-only.
///
/// ORDERING RULE (binding on every caller that also lists the SFU): read
/// this BEFORE the SFU listing, never after. The difference "recorded but not
/// listed" is what a caller treats as stale and deletes. Read after the
/// listing, a sibling that records between the listing and this read looks
/// stale and is deleted while live: S-3 WA-1 again. Read before, such a
/// sibling is in neither set, so it is never named, and
/// [`delete_voice_connections`]'s survivor scan keeps its state. The two
/// shapes:
///
/// - Survivor confirmation: `recorded` (first), then the listing, then
///   `delete_voice_connections(recorded − listed)`.
/// - Removal (moderation, disconnect, force-disconnect): `recorded` (first),
///   then `remove_user_if_present_sids`, then
///   `delete_voice_connections(returned ∪ (recorded − returned))`.
pub async fn recorded_voice_connections(
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<Vec<(String, String)>> {
    let recorded: BTreeMap<String, String> = get_connection()
        .await?
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;
    Ok(recorded
        .into_iter()
        .filter(|(_, identity)| user_id_from_participant_identity(identity.as_str()) == user_id)
        .collect())
}

/// ONE LiveKit connection of `user_id` left `channel` (voice-ingress
/// `participant_left`, and the ingress enforcement sites that evict exactly
/// one connection).
///
/// [`DELETE_VOICE_STATE`] in `connection` mode: the sid leaves the record,
/// and if another connection of the user is still recorded the answer is
/// [`ConnectionLeave::Survivor`] with NOTHING torn down and the mapping
/// re-pointed at the survivor. Otherwise [`ConnectionLeave::Last`], after
/// exactly the teardown [`delete_voice_state`] runs. An unknown sid while a
/// sibling is recorded is a `Survivor` too; a user the record has never seen
/// (connected before it existed) is a `Last`, as before S-3.
///
/// Watch-together (S-3 P2-4): the session ends with the HOST's voice state,
/// and it has to end BEFORE the teardown so the end event still reaches the
/// departing host's own devices. So the record is PEEKED first, read-only,
/// and the session is ended only when this sid is the user's last. The
/// script then re-decides atomically. A sibling that joins between the peek
/// and the script makes the peek's "last" wrong in the revoke direction only
/// (the session ends early), which is accepted.
///
/// A sid recorded as ANOTHER user's connection is refused with
/// `Err(InternalError)` and NOTHING written (S-3 WA-6): checked on the peek
/// first, so the watch session is not ended either, and again atomically by
/// the script, whose error reply comes before its first write. A sid with no
/// record at all is not refused: the HDEL is a no-op and the survivor scan
/// decides, as before.
///
/// Errors and the fallback follow [`delete_voice_state`] exactly: only a
/// refusal that proves the script never ran falls back, to
/// [`delete_voice_connection_unconditionally`]; every other error is
/// returned.
pub async fn delete_voice_connection(
    channel: &UserVoiceChannel,
    user_id: &str,
    sid: &str,
) -> Result<ConnectionLeave> {
    let recorded: BTreeMap<String, String> = get_connection()
        .await?
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;
    let foreign = recorded
        .get(sid)
        .filter(|identity| user_id_from_participant_identity(identity) != user_id);
    if let Some(identity) = foreign {
        log::error!(
            "refusing to remove connection {sid} for {user_id} in {}: it is recorded as \
             {identity}, another user's connection; nothing written",
            channel.id
        );
        return Err(create_error!(InternalError));
    }
    if another_connection_of(&recorded, user_id, sid).is_none() {
        watch::end_watch_session_if_host(channel, user_id).await;
    }

    let input = voice_connection_teardown_input(channel, user_id, sid);
    let mut invocation = DELETE_VOICE_STATE.prepare_invoke();
    for key in &input.keys {
        invocation.key(key);
    }
    for arg in &input.args {
        invocation.arg(arg);
    }

    let outcome = {
        let mut conn = get_connection().await?.into_inner();
        invocation.invoke_async::<_, i64>(&mut conn).await
    };

    match outcome {
        Ok(TEARDOWN_SURVIVOR) => Ok(ConnectionLeave::Survivor),
        Ok(0) => {
            log::info!(
                "voice state teardown for {user_id} in {} (connection {sid}) kept the \
                 per-server state: {} already names another channel (a late leave after a move)",
                channel.id,
                input.keys[0]
            );
            Ok(ConnectionLeave::Last)
        }
        Ok(_) => Ok(ConnectionLeave::Last),
        Err(error) if teardown_refused_a_foreign_connection(&error) => {
            log::error!(
                "refusing to remove connection {sid} for {user_id} in {}: the script found \
                 it recorded as another user's connection (recorded after the peek); nothing \
                 written",
                channel.id
            );
            Err(create_error!(InternalError))
        }
        Err(error) if teardown_script_error_allows_fallback(&error) => {
            // Logging only: the fallback below runs whatever the latch says.
            if TEARDOWN_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                log::debug!(
                    "voice state teardown script refused for {user_id} in {} (connection \
                     {sid}): {error}; non-atomic fallback",
                    channel.id
                );
            } else {
                log::error!(
                    "voice state teardown script refused for {user_id} in {} (connection \
                     {sid}): {error}; falling back to the non-atomic teardown. This server \
                     will not run the script, so every leave takes this path; logged once per \
                     process",
                    channel.id
                );
            }
            delete_voice_connection_unconditionally(channel, user_id, sid).await
        }
        Err(error) => {
            log::warn!(
                "voice state teardown script for {user_id} in {} (connection {sid}) failed: \
                 {error}; not a refusal that proves it never ran, so the error is returned",
                channel.id
            );
            Err(error).to_internal_error()
        }
    }
}

/// The FALLBACK for [`delete_voice_connection`], and ONLY that. DEGRADED:
/// the sid's HDEL, the survivor read and the re-point (or the teardown) are
/// separate round trips, so a sibling recorded or removed in between can make
/// the answer stale, and the teardown itself is
/// [`delete_voice_state_unconditionally`], which does not protect a newer
/// channel's per-server state after a move (and, S-3 WA-2, can erase a
/// sibling recorded after the survivor read; see there).
///
/// The WA-6 refusal holds here too, from a separate read: a sid recorded as
/// another user's is `Err(InternalError)` before any write.
async fn delete_voice_connection_unconditionally(
    channel: &UserVoiceChannel,
    user_id: &str,
    sid: &str,
) -> Result<ConnectionLeave> {
    let mut conn = get_connection().await?;
    let recorded_as: Option<String> = conn
        .hget(voice_connections_key(channel), sid)
        .await
        .to_internal_error()?;
    if let Some(identity) =
        recorded_as.filter(|recorded| user_id_from_participant_identity(recorded) != user_id)
    {
        log::error!(
            "refusing to remove connection {sid} for {user_id} in {} (fallback): it is \
             recorded as {identity}, another user's connection; nothing written",
            channel.id
        );
        return Err(create_error!(InternalError));
    }
    conn.hdel::<_, _, ()>(voice_connections_key(channel), sid)
        .await
        .to_internal_error()?;
    let connections: BTreeMap<String, String> = conn
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;

    if let Some(survivor) = another_connection_of(&connections, user_id, sid) {
        conn.hset::<_, _, _, ()>(format!("voice_identity:{}", &channel.id), user_id, survivor)
            .await
            .to_internal_error()?;
        return Ok(ConnectionLeave::Survivor);
    }

    delete_voice_state_unconditionally(channel, user_id).await?;
    Ok(ConnectionLeave::Last)
}

/// A SET of `user_id`'s connections is gone from `channel`, as decided by a
/// caller that listed the SFU (S-3 WA-R: moderation removal, disconnect,
/// force-disconnect, voice-ingress's Survivor confirmation).
///
/// [`DELETE_VOICE_STATE`] in `connections` mode, atomically:
///
/// - each sid in `sids` leaves `vc_conns:{channel}` ONLY if its recorded
///   identity belongs to `user_id` (equal to it, or it and `:` as a prefix).
///   A sid recorded as another user's is skipped and counted FOREIGN, and a
///   sid with no record is skipped and counted UNKNOWN; neither is an error,
///   and a nonzero FOREIGN count is logged at WARN (the caller handed over a
///   sid that is not this user's);
/// - then the survivor scan of [`delete_voice_connection`]: if ANY other
///   entry of the user is still recorded, the mapping is re-pointed at it and
///   the answer is [`ConnectionLeave::Survivor`] with NOTHING torn down.
///   Otherwise [`ConnectionLeave::Last`], after exactly the teardown
///   [`delete_voice_state`] runs, pointer guard included.
///
/// That survivor scan is the WA-1 fix. A sibling that recorded after the
/// caller's listing is in no set the caller could build, so it is never
/// named here, and it keeps the state its own record relied on. A whole-user
/// [`delete_voice_state`] in the same place erases it.
///
/// EMPTY `sids`: a pure survivor check, deliberately. `Survivor` (mapping
/// re-pointed, nothing torn down) when the user has any recorded entry in
/// this channel, else `Last` with the full teardown. The latter is what a
/// removal of a user the record has never seen (a legacy connection, or one
/// whose state outlived every connection) needs.
///
/// ORDERING RULE (binding on every caller): the sids come from a
/// [`recorded_voice_connections`] read taken BEFORE the SFU listing, never
/// after, so the only sids named are ones the caller KNOWS about:
///
/// - Survivor confirmation: `recorded_voice_connections` (first), then
///   `list_participants_reported`, then `stale = recorded − listed`, then
///   `delete_voice_connections(stale)`.
/// - Removal: `recorded_voice_connections` (first), then
///   `remove_user_if_present_sids`, then
///   `delete_voice_connections(returned ∪ (recorded − returned))`.
///
/// Read after the listing, a sibling that records in between is "recorded
/// but not listed", gets named as stale, and is deleted while live: WA-1.
///
/// Watch-together follows [`delete_voice_connection`]: the record is peeked
/// read-only, and the session ends BEFORE the script only when no entry of
/// the user would remain outside `sids`. The script re-decides atomically;
/// a sibling recorded between the peek and the script ends the session early
/// (the revoke direction), which is accepted.
///
/// Errors and the fallback follow [`delete_voice_state`] exactly: only a
/// refusal that proves the script never ran falls back, to the DEGRADED
/// [`delete_voice_connections_unconditionally`]; every other error is
/// returned.
pub async fn delete_voice_connections(
    channel: &UserVoiceChannel,
    user_id: &str,
    sids: &[String],
) -> Result<ConnectionLeave> {
    let recorded: BTreeMap<String, String> = get_connection()
        .await?
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;
    if another_connection_outside(&recorded, user_id, sids).is_none() {
        watch::end_watch_session_if_host(channel, user_id).await;
    }

    let input = voice_connections_teardown_input(channel, user_id, sids);
    let mut invocation = DELETE_VOICE_STATE.prepare_invoke();
    for key in &input.keys {
        invocation.key(key);
    }
    for arg in &input.args {
        invocation.arg(arg);
    }

    let outcome = {
        let mut conn = get_connection().await?.into_inner();
        invocation.invoke_async::<_, (i64, i64, i64)>(&mut conn).await
    };

    match outcome {
        Ok((code, foreign, unknown)) => {
            if foreign > 0 {
                log::warn!(
                    "voice state teardown for {user_id} in {}: skipped {foreign} sid(s) recorded \
                     as another user's connection and {unknown} with no record, of {} given",
                    channel.id,
                    sids.len()
                );
            } else if unknown > 0 {
                log::debug!(
                    "voice state teardown for {user_id} in {}: {unknown} of {} sid(s) had no \
                     record (legacy, or already gone)",
                    channel.id,
                    sids.len()
                );
            }
            match code {
                TEARDOWN_SURVIVOR => Ok(ConnectionLeave::Survivor),
                0 => {
                    log::info!(
                        "voice state teardown for {user_id} in {} ({} connection(s)) kept the \
                         per-server state: {} already names another channel (a late leave after \
                         a move)",
                        channel.id,
                        sids.len(),
                        input.keys[0]
                    );
                    Ok(ConnectionLeave::Last)
                }
                _ => Ok(ConnectionLeave::Last),
            }
        }
        Err(error) if teardown_script_error_allows_fallback(&error) => {
            // Logging only: the fallback below runs whatever the latch says.
            if TEARDOWN_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) {
                log::debug!(
                    "voice state teardown script refused for {user_id} in {} ({} \
                     connection(s)): {error}; non-atomic fallback",
                    channel.id,
                    sids.len()
                );
            } else {
                log::error!(
                    "voice state teardown script refused for {user_id} in {} ({} \
                     connection(s)): {error}; falling back to the non-atomic teardown. This \
                     server will not run the script, so every leave takes this path; logged \
                     once per process",
                    channel.id,
                    sids.len()
                );
            }
            delete_voice_connections_unconditionally(channel, user_id, sids).await
        }
        Err(error) => {
            log::warn!(
                "voice state teardown script for {user_id} in {} ({} connection(s)) failed: \
                 {error}; not a refusal that proves it never ran, so the error is returned",
                channel.id,
                sids.len()
            );
            Err(error).to_internal_error()
        }
    }
}

/// The FALLBACK for [`delete_voice_connections`], and ONLY that. DEGRADED,
/// exactly as [`delete_voice_connection_unconditionally`] is (S-3 WA-2): the
/// ownership read, the HDEL, the survivor read and the re-point (or the
/// teardown) are separate round trips, so a sibling recorded or removed in
/// between can make the answer stale; and the teardown is
/// [`delete_voice_state_unconditionally`], which does not protect a newer
/// channel's per-server state after a move and can erase a sibling recorded
/// after the survivor read (the WA-1 outcome, in a window of a few round
/// trips, on a server that refuses the script).
///
/// Same rules as the script otherwise: only sids recorded as this user's
/// are HDELed (foreign and unknown ones are skipped), then any remaining
/// entry of the user is a `Survivor`.
async fn delete_voice_connections_unconditionally(
    channel: &UserVoiceChannel,
    user_id: &str,
    sids: &[String],
) -> Result<ConnectionLeave> {
    let mut conn = get_connection().await?;
    let recorded: BTreeMap<String, String> = conn
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;
    let theirs: Vec<&String> = sids
        .iter()
        .filter(|sid| {
            recorded
                .get(*sid)
                .is_some_and(|identity| user_id_from_participant_identity(identity) == user_id)
        })
        .collect();
    if !theirs.is_empty() {
        conn.hdel::<_, _, ()>(voice_connections_key(channel), theirs)
            .await
            .to_internal_error()?;
    }
    let connections: BTreeMap<String, String> = conn
        .hgetall(voice_connections_key(channel))
        .await
        .to_internal_error()?;

    if let Some(survivor) = another_connection_outside(&connections, user_id, sids) {
        conn.hset::<_, _, _, ()>(format!("voice_identity:{}", &channel.id), user_id, survivor)
            .await
            .to_internal_error()?;
        return Ok(ConnectionLeave::Survivor);
    }

    delete_voice_state_unconditionally(channel, user_id).await?;
    Ok(ConnectionLeave::Last)
}

pub async fn delete_channel_voice_state(
    channel: &UserVoiceChannel,
    user_ids: &[String],
) -> Result<()> {
    let parent_id = channel.server_id.as_ref().unwrap_or(&channel.id);

    // The whole call is going — end any watch-together session with it.
    watch::end_watch_session_for_channel(channel).await;

    let mut pipeline = Pipeline::new();
    pipeline.del(format!("vc_members:{}", &channel.id));
    pipeline.del(format!("node:{}", &channel.id));
    // Covers `room_finished` and `reconcile_channel`, which pass no user ids:
    // the whole call is gone, so every screen-leg marker goes with it.
    pipeline.del(format!("vc_leg:{}", &channel.id));
    // And every identity mapping, for the same reason and by the same DEL.
    // Note this is unconditional on `user_ids` exactly as the three keys above
    // it are: this function already treats the call as gone wholesale, whatever
    // subset of members the caller happened to name (`delete_voice_channel`
    // names the roster, `room_finished` and `reconcile_channel` name nobody),
    // so a per-user HDEL here would be the odd one out and would leak the rest.
    // Identical in effect to `clear_voice_participant_identities`, which the
    // two ingress callers invoke on the following line and may keep doing —
    // DEL is idempotent, and their explicit call is what covers the paths that
    // do not come through here.
    pipeline.del(format!("voice_identity:{}", &channel.id));
    // And the whole connection record (S-3 D-1), for the same reason again:
    // `room_finished` and `reconcile_channel` name nobody, and this DEL is
    // the only thing that reaches the entries they leave behind (P2-1).
    pipeline.del(voice_connections_key(channel));
    // Same for the session records: nobody owns a participant in a call that
    // is gone.
    pipeline.del(voice_session_key(&channel.id));

    for user_id in user_ids {
        let unique_key = format!("{user_id}:{parent_id}");

        let mut keys = voice_state_keys(&unique_key);
        // Draw consent dies with the call (rev-3 review).
        keys.push(format!("annotations_allow:{}:{}", &channel.id, user_id));
        keys.push(unique_key);

        pipeline.srem(format!("vc:{user_id}"), channel).del(keys);
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

    if let Some(recording) = &partial.recording {
        pipeline.set(format!("recording:{unique_key}"), recording);
    }

    if let Some(rc_capable) = &partial.rc_capable {
        pipeline.set(format!("rc_capable:{unique_key}"), rc_capable);
    }

    if let Some(watching) = &partial.watching {
        pipeline.set(format!("watching:{unique_key}"), watching);
    }

    pipeline
        .query_async::<_, ()>(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()?;

    // Draw consent is scoped to the SHARE it was granted on (rev-3 review):
    // when the screen-video publication ends, the sharer's annotation
    // allowlist ends with it — otherwise the next share in this channel
    // silently resurrects grants the sharer no longer remembers making.
    // The consent event fans only if a list actually existed, so ordinary
    // share stops (the overwhelmingly common case) cost nothing extra; it
    // is what flips remote clients' draw affordances off and drops any
    // still-rendered ink at once.
    if partial.screen_video == Some(false)
        && annotations::clear_allowed_annotators(&channel.id, user_id).await?
    {
        if let Some(members) = get_voice_channel_members(channel).await? {
            for member_id in members {
                crate::events::client::EventV1::CallAnnotationConsent {
                    channel_id: channel.id.clone(),
                    sharer_id: user_id.to_string(),
                    allowed: Vec::new(),
                }
                .private(member_id)
                .await;
            }
        }
    }

    Ok(())
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

    #[allow(clippy::type_complexity)]
    let (
        joined_at,
        is_publishing,
        is_receiving,
        screensharing,
        camera,
        screen_video,
        recording,
        rc_capable,
        watching,
    ): (
        Option<i64>,
        Option<bool>,
        Option<bool>,
        Option<bool>,
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
            format!("recording:{unique_key}"),
            format!("rc_capable:{unique_key}"),
            format!("watching:{unique_key}"),
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
            // Same rule, and fail-closed in the useful direction: an
            // unreadable recording key reads as "not recording" rather than
            // dropping the participant's whole voice state.
            recording: recording.unwrap_or(false),
            // Same rule again: absent (states created before this key
            // existed, or a lost key) reads as "capability not claimed",
            // never as a dropped participant.
            rc_capable: rc_capable.unwrap_or(false),
            // Same rule: absent reads as "not in a watch party", never as a
            // dropped participant.
            watching: watching.unwrap_or(false),
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

/// What a server-authoritative voice move actually did.
///
/// The non-`Moved` arms are ordinary outcomes, not failures: the callers
/// that matter are a moderator route (where "they already left" is a no-op,
/// not a 500) and the AFK sweep (which runs on a timer against a population
/// that is shifting under it). Raising on either would turn a lost race into
/// an error the caller has to special-case back into success.
///
/// The move is announced to ONE session, the one recorded as owning the
/// target's participant in the source (`voice_session:{from}`, the caller's
/// `expected_session`), and never to every session of the user (media-e2ee
/// final audit F1).
///
/// An outcome other than `Moved` is NOT a promise that nothing was written.
/// Every refusal is answered before the first write EXCEPT the two checks
/// right before the announcement: for a device token, the device binding
/// re-read (media-e2ee S6M-3), then the owner re-check answer
/// `NotConnected` after the session carry-over, the destination's node pin
/// and room, the remote-control revoke and the mint (see `NotConnected`). A
/// carry the source no longer allows answers `NotConnected` too, with
/// nothing written.
///
/// A failure AFTER the first write is an `Err`, not an outcome. The one that
/// matters is the admission-key write (merge slice P2A-5): when it fails the
/// remote-control grant has been revoked, the session record carried, the
/// destination node pinned and its room created, no event has gone out and
/// the target is still in the source. The route answers 500 and the sweep
/// retries. A failed mint is the same, minus the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceMoveOutcome {
    /// The target was moved. `node` is the LiveKit node the destination room
    /// lives on, `from` the channel they were pulled out of.
    ///
    /// Precisely: ONE connection of theirs, the one chosen from the SFU's
    /// participant list for `from`, was announced to the owning session, with
    /// a token only for exactly the seat kind recorded with that session at
    /// its join (merge slice RRB-1, [`move_event_delivery`]): a bare token
    /// only when the recorded seat is bare and the chosen connection IS the
    /// target's bare seat; a device token only when the recorded seat is that
    /// device, it is the chosen connection's device, media E2EE is on, and
    /// the device is bound to the owning session (read when the move plans,
    /// and again right before the owner re-check, media-e2ee S6M-3). A record
    /// with no readable seat kind (legacy or unknown), or any other
    /// combination, gets no token, and the client joins through `join_call`.
    /// Every connection that list reported for that
    /// account in `from` was removed from it (the moved one included;
    /// "already gone" counts as removed). Any other connection was therefore
    /// ejected from the call rather than moved. An account normally holds
    /// exactly one, so normally those are the same sentence; they come apart
    /// when two sessions raced the join front door, and the eviction leg of
    /// `move_user_to_voice_channel_expecting` says why that resolves this
    /// way.
    ///
    /// There is no degraded path behind this variant: a listing that fails
    /// fails the move before anything is written, and a real failure to
    /// remove any LISTED connection is returned as an error (only a derived,
    /// unlisted screen leg is best-effort), so `Moved` is only ever reported
    /// for a move whose every listed connection was removed or already gone.
    /// The variant carries no eviction count on purpose — it is a transport
    /// detail no caller can act on.
    Moved { node: String, from: String },
    /// The target holds no voice state in the destination's server; or is no
    /// longer in the source the caller decided about; or the channel they
    /// are recorded in has no LiveKit node behind it any more; or the SFU
    /// says that room does not exist, or lists no connection of theirs in it.
    /// Those are answered before the move writes anything.
    ///
    /// Also the answer when the owning session changed under the move: the
    /// carry-over found the source record naming another session (nothing
    /// written yet), or the re-check right before the announcement did (a
    /// `join_call` from another session, its `force_disconnect` kick, or a
    /// disconnect in `member_edit`, since the move read the record); and when
    /// the device a device token was minted for is no longer bound to the
    /// owning session when it is re-read, right before that re-check (revoked
    /// or re-bound, media-e2ee S6M-3).
    /// Those checks run AFTER the carry, the destination's node pin and room,
    /// the remote-control release and the mint: those stay done (the grant
    /// revoked, which is the safe direction), the token is dropped
    /// unpublished, nothing is announced, marked or evicted, and the target
    /// stays where they are.
    NotConnected,
    /// The target is already sitting in the destination.
    AlreadyPresent,
    /// Nobody could be told about the move: no session is recorded as owning
    /// the target's participant in the source (a join from before the record
    /// existed), so no session can be handed a token. The move was done as
    /// the disconnect it amounts to: the remote-control grant released and
    /// every listed connection evicted from the source, with no node pin,
    /// room, mint, admission key, marker or event for the destination. The
    /// route answers 200. Never for `MovePolicy::Sweep`, which is refused
    /// before any write instead (the sweep skips such a member itself), and
    /// never for `MovePolicy::SelfMove`, which is refused `NotAuthenticated`
    /// without an owner.
    Disconnected,
    /// Refused before any write (merge slice P2A-3, M2B-1): the owning
    /// session can only be told WITHOUT a token, so its client would have to
    /// join through `join_call`, and `join_call` would refuse the target:
    /// no Connect on the destination, or the destination's `max_users` is
    /// reached and the target lacks `ManageChannel` (`join_call`'s own rule,
    /// [`join_call_occupancy_refuses`]). Carried out, the move would evict
    /// the target into no call at all. In practice a moderator or sweep move
    /// (a self-move is held to both rules at admission already); the route
    /// maps it to a 4xx, the sweep to a policy refusal with its normal
    /// backoff.
    TargetCannotJoin,
}

/// Who is asking for a voice move, which decides the TARGET's admission to
/// the destination (merge slice RT-3 / F3, rulings D0 and 09-27).
///
/// Every policy requires the target to be a member who can VIEW the
/// destination, and every policy is held to the call-admission caps
/// (`assert_call_caps_admit`). They differ on Connect and `max_users`:
///
/// - `Moderator` and `Sweep`: the target needs no Connect on the destination
///   (a timeout channel, an AFK channel nobody may join), and the
///   destination's `max_users` does not apply. The voice-ingress D-3
///   re-check then admits the moved connection through the move admission
///   key ([`voice_connect_still_allowed`]).
/// - `SelfMove`: a join by the target in all but name, so it needs Connect
///   and obeys `max_users`, with the join front door's `ManageChannel`
///   exemption. It also carries the session the request came in on, and
///   the move itself refuses it unless that is the session recorded as
///   owning the participant (merge slice SEC2-2, B4).
///
/// Carried as a value rather than a `bool`, and passed to the move and its
/// pre-flight alike (`assert_voice_move_admissible`), so the two cannot
/// admit under different rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MovePolicy<'a> {
    /// A moderator (`MoveMembers`) moving somebody else.
    Moderator,
    /// A member moving themselves. `request_session` is the id of the
    /// session the request came in on: `None` when there is none (a bot) or
    /// it is not the target's own. The move goes ahead only when it is the
    /// session recorded as owning the participant in the source
    /// ([`self_move_from_owning_session`], checked inside the move after
    /// the `AlreadyPresent` and expected-source answers and before anything
    /// else); otherwise `NotAuthenticated`. With no owner recorded it is
    /// refused too, never done as a disconnect.
    SelfMove { request_session: Option<&'a str> },
    /// The crond AFK sweep, which has no acting user.
    Sweep,
}

impl MovePolicy<'_> {
    /// Whether the target must hold Connect on the destination, and obey
    /// its `max_users`.
    fn admits_like_a_join(self) -> bool {
        match self {
            MovePolicy::SelfMove { .. } => true,
            MovePolicy::Moderator | MovePolicy::Sweep => false,
        }
    }
}

/// The side-effect-free half of a voice move: everything that can refuse it,
/// and nothing that can change anything.
///
/// Kept separate from the move itself so callers can refuse BEFORE they
/// mutate. `member_edit` relies on this: it validates here, then writes the
/// member document, then moves — so a refusal leaves the member untouched.
///
/// That only holds because the route refuses to combine `voice_channel` with
/// the fields that move these very permissions (`roles`, `timeout`,
/// `can_publish`, `can_receive`). Combined, the pre-flight and the move read
/// two DIFFERENT member documents — the move re-reads it deliberately, so the
/// token is minted from permissions that are current — and the second reading
/// can refuse after the first has already committed the edit. A refusal that
/// leaves a member timed out but not moved is not "untouched".
///
/// Returns what the gates already had to compute, so the move does not
/// recompute it. The destination `PermissionValue` in particular is used at
/// both permission gates, at the `max_users` exemption and again to mint the
/// token; it used to be calculated twice, 130 lines apart, which is how the
/// two copies came to disagree about whose permissions they were.
#[derive(Debug)]
struct VoiceMoveAdmission {
    /// The TARGET's permissions on the DESTINATION channel.
    permissions: PermissionValue,
}

/// Whether a destination's `max_users` cap refuses `target_id`.
///
/// Pure, and deliberately so: the roster read that feeds it needs Redis,
/// which the unit tests do not have, while the decision itself is the part
/// that was wrong and is worth pinning.
///
/// `members` is the destination's live roster; `target_manages_channel` is
/// the `ManageChannel` exemption the join front door grants.
fn occupancy_cap_refuses(
    members: &[String],
    max_users: usize,
    target_id: &str,
    target_manages_channel: bool,
) -> bool {
    // Already in the room: admitting them cannot grow the roster, so the cap
    // has nothing to say about them. `video_cap_would_refuse` and
    // `mls_cap_would_refuse` have both carried this exemption from the day
    // they landed; the occupancy cap did not, and that asymmetry is the whole
    // defect. An AFK channel with `max_users: 5` holding five idle members
    // refused every one of those five, on every sweep tick, because
    // `5 >= 5` was answered before anyone asked whether they were already
    // there — and on the route it turned "move X to where X already is" into
    // a 400 the moment the channel was capped and full.
    if members.iter().any(|member| member == target_id) {
        return false;
    }

    members.len() >= max_users && !target_manages_channel
}

/// `join_call`'s OWN occupancy rule (`crates/delta/src/routes/channels/
/// voice_join.rs`), exactly: refused when the channel has a `max_users` cap
/// AND a recorded roster (`get_voice_channel_members`) at or over it, unless
/// the joiner holds `ManageChannel` there. No roster recorded, or no cap, is
/// never full.
///
/// Deliberately NOT [`occupancy_cap_refuses`]: `join_call` has no
/// already-present exemption, and this answers what `join_call` will answer.
/// A tokenless move (merge slice M2B-1) sends its target to `join_call`, so
/// the move asks this first and refuses what `join_call` would refuse,
/// instead of evicting the target into no call. The join route calls this
/// very function, exactly once (merge slice RRB-5), and no longer spells the
/// rule out itself: `the_tokenless_move_asks_join_calls_own_occupancy_rule`
/// requires the one call and refuses the inline form it replaced (merge
/// slice M2C-4), so the two cannot drift. Pure, so the rule is pinned by
/// value.
pub fn join_call_occupancy_refuses(
    members: Option<&[String]>,
    max_users: Option<usize>,
    joiner_manages_channel: bool,
) -> bool {
    members
        .zip(max_users)
        .is_some_and(|(members, max_users)| members.len() >= max_users)
        && !joiner_manages_channel
}

async fn admit_voice_move(
    db: &Database,
    target: &User,
    destination: &Channel,
    policy: MovePolicy<'_>,
) -> Result<VoiceMoveAdmission> {
    // Server channels only. This is the one thing keeping the move primitive
    // off DMs and Groups, both of which report `server() == None` — and a DM
    // is an E2EE two-seat call that nothing may drag a third party into.
    let Some(server_id) = destination.server() else {
        return Err(create_error!(UnknownChannel));
    };

    // The destination must actually be a voice channel. The join front door
    // has always checked this (`voice_join`); the move path never did, so a
    // moderator could "move" someone into a text channel and the code below
    // would happily open a LiveKit room named after it.
    let Some(voice_info) = destination.voice() else {
        return Err(create_error!(NotAVoiceChannel));
    };

    // Evaluated against the TARGET, not whoever asked for the move. The
    // acting user's Connect is not the question — they are not the one who
    // ends up in the room — and a daemon sweep has no acting user at all.
    // Note the query is built from `(db, target)` with no `.member(...)`:
    // `DatabasePermissionQuery` fetches the member lazily, so this reads the
    // member document as it stands NOW, including an edit the caller just
    // committed. Handing it a caller-supplied `Member` would mint the token
    // from pre-edit permissions.
    let mut query = DatabasePermissionQuery::new(db, target).channel(destination);
    let permissions = calculate_channel_permissions(&mut query).await;

    // Membership, explicitly, for every policy. The calculus answers a
    // non-member with no permission at all, EXCEPT for a privileged account,
    // which it waves through with GrantAllSafe before it looks at membership.
    // A move lands the target in a server's call, so it needs the member
    // document a ban or a kick deletes. Fails closed on any read error. A
    // privileged NON-member is therefore `NotFound` here, under every policy
    // (pinned: `a_privileged_non_member_is_not_found_for_a_move`).
    db.fetch_member(server_id, &target.id).await?;

    // `ViewChannel` is required for EVERY policy, and it is about what
    // happens AFTER the move lands rather than about the move itself: bonfire
    // filters a channel the user cannot view out of `Ready`, so the client's
    // `channels.get(to)` comes back undefined and the move UI tells them to
    // open a channel that structurally is not there — out of the call they
    // were in, with no route back.
    //
    // A move is not a join: the target never chose this destination, so the
    // gate has to hold for them rather than merely be representable to them.
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Connect only when the move is a join by the target in all but name
    // (a self-move). A moderator or the AFK sweep may move a target into a
    // channel the target could not join themselves (ruling D0-1: timeout
    // channels; 09-27: the sweep moves under moderator rules); the ingress
    // re-check then admits the moved connection through the admission key
    // the move writes, and nothing else.
    if policy.admits_like_a_join() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;
    }

    // The same occupancy cap the join front door enforces, with the same
    // `ManageChannel` exemption, for a self-move only (ruling D0-2: a
    // moderator's move, and the sweep's, bypass `max_users`, as on Discord).
    // Without it a self-move walks straight past a limit a join is refused
    // at.
    //
    // Only difference from the join leg: the members read is skipped when
    // the channel has no cap, because there is nothing to compare it to.
    //
    // The decision itself lives in `occupancy_cap_refuses`, which carries the
    // already-present exemption the other two caps have always had. `None`
    // here still means "no roster recorded", which is not a full room.
    if let (true, Some(max_users)) = (policy.admits_like_a_join(), voice_info.max_users) {
        let refused = get_voice_channel_members(&UserVoiceChannel::from_channel(destination))
            .await?
            .is_some_and(|members| {
                occupancy_cap_refuses(
                    &members,
                    max_users,
                    &target.id,
                    permissions.has(ChannelPermission::ManageChannel as u64),
                )
            });

        if refused {
            return Err(create_error!(CannotJoinCall));
        }
    }

    Ok(VoiceMoveAdmission { permissions })
}

/// Every admission refusal a voice move can raise, with no side effects, so a
/// caller can run them before it mutates anything.
///
/// `move_user_to_voice_channel_expecting` runs the identical set — it goes
/// through the same `admit_voice_move` under the same `policy` (pinned) and
/// the same `assert_call_caps_admit` — so this is a pre-flight, never a
/// substitute for it. The caller must pass the policy it will move under.
/// Nothing here is a TOCTOU-free promise: the caps in particular are
/// check-then-act, with the voice-ingress backstop closing the admission
/// race. The move can still refuse what only it can see (the SFU listing,
/// the owning session, `VoiceMoveOutcome::TargetCannotJoin`).
pub async fn assert_voice_move_admissible(
    db: &Database,
    target: &User,
    destination: &Channel,
    policy: MovePolicy<'_>,
) -> Result<()> {
    admit_voice_move(db, target, destination, policy).await?;

    // Call-admission caps (D12 video-participant cap + T-20 MLS SFU-token
    // coupling), enforced against the DESTINATION for the TARGET. A
    // privileged door must not bypass a cap the front door enforces.
    assert_call_caps_admit(db, &UserVoiceChannel::from_channel(destination), &target.id).await
}

/// Whether `user_id` may STILL connect to `channel_id`, re-checked when the
/// SFU reports the connection (voice-ingress `participant_joined`, S-3 D-3).
///
/// A join token lives for seconds, and a ban, kick or Connect denial that
/// lands between the mint and the SFU join is otherwise never seen: the
/// connection arrives with a grant minted before the change.
///
/// The query is built EXACTLY as [`admit_voice_move`] and the join route
/// build theirs: `(db, user)` plus the channel, with the member fetched
/// LAZILY by the calculus. An explicit member lookup here would refuse every
/// DM and Group caller, who have no member document, and would hand the
/// calculus a document instead of the current one. The calculus covers every
/// kind of channel: a DM or Group participant, the server owner (GrantAllSafe)
/// and a bot with Connect are allowed; a non-member or a member denied
/// Connect is not.
///
/// A user or channel that no longer exists is `Ok(false)`: nobody may be
/// connected to a deleted channel, and a deleted account holds nothing.
/// Any other read failure is returned, and the caller fails CLOSED on it.
///
/// THE MOVE ADMISSION (merge slice P2A-4, amending D-3). A moderator's move,
/// and the AFK sweep's, may put a target who lacks Connect into a channel
/// (`MovePolicy`); the calculus alone would evict that connection here and
/// leave the target in no call while the move reported success. Such a move
/// writes `move_admit:{user}:{channel}` holding the identity it minted the
/// token for ([`set_move_admission`]), and a connection without Connect is
/// still admitted when ALL of these hold:
///
/// - the channel is a server channel and the user is still a MEMBER of its
///   server (a ban or kick since the move deletes the member document);
/// - the user can still VIEW the channel;
/// - the key is present, unexpired, and names EXACTLY the joining
///   `identity` (another device of the user, or a bare seat when a device
///   seat was moved, is not admitted by it).
///
/// The key is PEEKED, never drained: livekit's reconnect of the moved
/// connection within [`MOVE_ADMISSION_TTL_SECS`] is admitted again. A failed
/// peek is returned, and the caller fails closed. A self-move never writes
/// the key (it needs Connect to be admitted at all), and the `moved_to`
/// marker is a roster label, never an admission.
///
/// Residual, accepted: once the key has expired, a later full livekit
/// reconnect of the moved connection is re-checked like any other join, and
/// evicted while Connect is still denied.
pub async fn voice_connect_still_allowed(
    db: &Database,
    channel_id: &str,
    user_id: &str,
    identity: &str,
) -> Result<bool> {
    let user = match db.fetch_user(user_id).await {
        Ok(user) => user,
        Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
            return Ok(false)
        }
        Err(error) => return Err(error),
    };
    let channel = match db.fetch_channel(channel_id).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
            return Ok(false)
        }
        Err(error) => return Err(error),
    };

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    if permissions.has_channel_permission(ChannelPermission::Connect) {
        return Ok(true);
    }

    // The move admission, above. Every condition fails closed.
    let Some(server_id) = channel.server() else {
        return Ok(false);
    };
    // THIS is what refuses a non-member and a member banned or kicked since
    // the move: the calculus answers a user with no member document with no
    // permission at all, `ViewChannel` included (pinned, with a member whose
    // `ViewChannel` was revoked while the key is valid:
    // `a_move_admission_needs_view_and_its_own_channel`).
    if !permissions.has_channel_permission(ChannelPermission::ViewChannel) {
        return Ok(false);
    }
    // Defense in depth, unreachable today: every user without a member
    // document was refused just above, and the one account the calculus
    // grants without one (a privileged account, GrantAllSafe) holds Connect
    // and was admitted before the move admission was consulted at all. Kept
    // so a change to the calculus cannot quietly admit a non-member here.
    match db.fetch_member(server_id, user_id).await {
        Ok(_) => {}
        Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
            return Ok(false)
        }
        Err(error) => return Err(error),
    }

    Ok(peek_move_admission(user_id, channel_id).await?.as_deref() == Some(identity))
}

/// Lifetime of a move admission key, in seconds (merge slice P2A-4).
///
/// At least [`MOVE_TOKEN_TTL`] plus slack: the moved client connects with a
/// token that lives `MOVE_TOKEN_TTL`, and its `participant_joined` webhook
/// reaches voice-ingress after the connect, so the key must outlive the
/// token by that delay. Below the AFK sweep's 30 s per-member move claim
/// (`AFK_MOVE_CLAIM_TTL_SECS` in crond), but that compares the lifetimes,
/// not the expiries (merge slice M2C-3, FXA-4): the claim is taken before
/// the move starts, and the key is written late in a move that may run for
/// up to `AFK_MOVE_TIMEOUT` (20 s), so the key can outlive the claim by up
/// to `AFK_MOVE_TIMEOUT` minus the claim's lead over the key's lifetime,
/// 20 - (30 - 20) = 10 s, and a sweep move retried in that window may find
/// the admission the attempt before it left. Harmless: the key admits one
/// identity (the seat that attempt minted for) into one channel (that
/// attempt's destination) and nothing wider; the server's AFK channel can
/// change between the attempts, and then the key does not even name the
/// retry's destination. Pinned on both lifetimes only
/// (`the_move_admission_key_outlives_the_token`).
pub const MOVE_ADMISSION_TTL_SECS: usize = 20;

/// The move admission key of `user_id` for `channel_id`.
fn move_admission_key(user_id: &str, channel_id: &str) -> String {
    format!("move_admit:{user_id}:{channel_id}")
}

/// Write the move admission for `user_id` into `channel_id`, naming the
/// exact `identity` the move's token was minted for. Only the move writes it
/// (see [`voice_connect_still_allowed`]). Deploy note: a KeyDB ACL must
/// allow the `move_admit:` prefix.
async fn set_move_admission(user_id: &str, channel_id: &str, identity: &str) -> Result<()> {
    write_move_admission(user_id, channel_id, identity, MOVE_ADMISSION_TTL_SECS).await
}

/// [`set_move_admission`] with the lifetime as a parameter, so a test can
/// watch a key expire without waiting out the real one.
async fn write_move_admission(
    user_id: &str,
    channel_id: &str,
    identity: &str,
    ttl_secs: usize,
) -> Result<()> {
    get_connection()
        .await?
        .set_ex(move_admission_key(user_id, channel_id), identity, ttl_secs)
        .await
        .to_internal_error()
}

/// The identity a move admitted `user_id` into `channel_id` with, if an
/// unexpired admission exists. A plain GET: a peek never consumes the key.
async fn peek_move_admission(user_id: &str, channel_id: &str) -> Result<Option<String>> {
    get_connection()
        .await?
        .get(move_admission_key(user_id, channel_id))
        .await
        .to_internal_error()
}

/// Whether a move under `policy` must write the admission key: a moderator
/// or sweep move of a target who could not have joined the destination
/// themselves. Pure, so the rule is pinned by value.
fn needs_move_admission(policy: MovePolicy, target_may_connect: bool) -> bool {
    !policy.admits_like_a_join() && !target_may_connect
}

/// The LiveKit identity a token minted for `device_id` carries: `{user}` for
/// a bare seat, `{user}:{device}` for a device seat. The same format
/// `VoiceClient::create_token` builds (pinned against it).
fn move_token_identity(user_id: &str, device_id: Option<&str>) -> String {
    match device_id {
        Some(device_id) => format!("{user_id}:{device_id}"),
        None => user_id.to_string(),
    }
}

/// Whether media E2EE (calls) is switched on: EXACTLY
/// `features.e2ee_enabled && features.media_e2ee_enabled`, the rule delta's
/// `require_media_e2ee_enabled` applies to every device-qualified join
/// (and delegates to this). Read by the move itself (merge slice F9), so the
/// sweep and the route cannot disagree about it, and no caller hands in a
/// `bool`.
pub async fn media_e2ee_enabled() -> bool {
    let features = &config().await.features;
    features.e2ee_enabled && features.media_e2ee_enabled
}

/// One SFU participant a move has to eject from the source room.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VoiceEviction {
    /// The exact identity to hand `VoiceClient::remove_identity_if_present`.
    identity: String,
    /// Whether the SFU itself named this identity in its participant list.
    ///
    /// The distinction decides what a failed removal MEANS. "Not in the room"
    /// is never a failure for either kind — `remove_identity_if_present`
    /// answers it as `Ok(false)`, with no error, no log and no Sentry event —
    /// so this only matters for a REAL failure (the SFU errored or could not
    /// be reached). A reported identity is a connection the SFU has just told
    /// us is in the room, so a real failure to remove it fails the move. A
    /// derived screen leg is speculative — almost nobody has one — so a real
    /// failure on it does not. Either way the failure is logged at WARN
    /// twice, once by `remove_identity_if_present` and once by the move with
    /// the target and this classification, and never reported to Sentry;
    /// [`eviction_result`] then fails the move on a reported one and discards
    /// a derived one.
    reported: bool,
}

/// What a move's evictions amount to, once EVERY one has been attempted.
///
/// `Ok(true)` (removed) and `Ok(false)` (not in the room) are both success,
/// for either kind of eviction: "not in the room" is the expected answer for
/// the moving connection, which leaves `from` on the move event by design and
/// often beats its own removal to the SFU, and the ordinary answer for a
/// derived leg nobody has. Counting it as a failure turned a committed,
/// successful move into a 500.
///
/// An `Err` on a REPORTED eviction fails the move; an `Err` on a derived,
/// unreported leg is discarded (see [`VoiceEviction::reported`]). When
/// several fail, the FIRST reported failure is the one returned.
///
/// Takes the outcomes after the fact rather than deciding inside the loop,
/// so the loop has no early exit to grow: every removal is issued before
/// this runs. Pure and generic over the error, so the rule is pinned without
/// an SFU.
fn eviction_result<E>(
    outcomes: impl IntoIterator<Item = (VoiceEviction, std::result::Result<bool, E>)>,
) -> std::result::Result<(), E> {
    let mut failure = None;

    for (eviction, outcome) in outcomes {
        match outcome {
            Ok(_) => {}
            Err(_) if !eviction.reported => {}
            Err(error) => {
                failure.get_or_insert(error);
            }
        }
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Every eviction needed to clear `user_id` out of a room whose live
/// participant identities are `identities`, in the order they must be issued.
///
/// Pure, and deliberately so: the participant list it consumes comes from a
/// LiveKit RPC that the unit tests have no way to answer, while the selection
/// itself is the part that was wrong and is worth pinning. The same split
/// `occupancy_cap_refuses` already uses.
///
/// Two properties it exists to hold:
///
/// - **Every connection, not the mapped one.** The predicate is
///   `user_id_from_participant_identity`, so a bare `{user}` and a
///   device-qualified `{user}:{device}` of the same account both select — which
///   is the entire point, since those two are not duplicate identities to
///   LiveKit and can therefore sit in one room together.
/// - **Legs go with their owners, and a leg is never mistaken for an owner.**
///   A reported leg is evicted on its own account; a leg is additionally
///   DERIVED from each reported primary, because a leg that joined after the
///   listing was taken is not in it and would otherwise keep streaming into a
///   room its owner has left. Deriving from a leg is refused outright:
///   `screen_leg_identity("{user}:{device}:screen")` invents a fourth segment
///   the SFU has never heard of, and issuing it would be a removal aimed at
///   nothing while the real leg stayed up.
///
/// Legs are emitted BEFORE their primary, the order every removal of a
/// connection uses (`VoiceClient::remove_connection_if_present` as well): the
/// leg is a helper of the primary, and tearing the owner down first is what
/// leaves an orphan publishing.
fn eviction_targets<I: IntoIterator<Item = String>>(
    identities: I,
    user_id: &str,
) -> Vec<VoiceEviction> {
    let mut targets: Vec<VoiceEviction> = Vec::new();

    // Linear scans over a call roster — a handful of entries, and correctness
    // here is worth more than a hash set's constant factor.
    fn push(targets: &mut Vec<VoiceEviction>, identity: String, reported: bool) {
        if let Some(existing) = targets
            .iter_mut()
            .find(|target| target.identity == identity)
        {
            // A derived leg that the SFU also reported is REPORTED: the
            // stronger claim wins, so a removal we know must succeed is never
            // downgraded to best-effort by the order the list happened to
            // arrive in.
            existing.reported |= reported;
            return;
        }

        targets.push(VoiceEviction { identity, reported });
    }

    for identity in identities {
        if user_id_from_participant_identity(&identity) != user_id {
            continue;
        }

        if !is_screen_leg(&identity) {
            push(&mut targets, screen_leg_identity(&identity), false);
        }

        push(&mut targets, identity, true);
    }

    targets
}

/// A room's SFU roster grouped by OWNING USER: user id -> every identity of
/// theirs the SFU listed, in listed order (S-3 D-4). Screen legs are KEPT,
/// under their owner: the permission sync pushes a leg its own
/// leg-restricted grant, so it has to see them.
///
/// Ownership is `user_id_from_participant_identity`, never a string prefix:
/// `uu:B` belongs to `uu`, not to `u`. Pure; consumed by the roster-driven
/// permission sync ([`sync_voice_permissions`] and the single-user
/// [`sync_user_voice_permissions`]).
pub(crate) fn roster_connections(
    identities: impl IntoIterator<Item = String>,
) -> BTreeMap<String, Vec<String>> {
    let mut roster: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for identity in identities {
        roster
            .entry(user_id_from_participant_identity(&identity).to_string())
            .or_default()
            .push(identity);
    }

    roster
}

/// Which of the target's connections in the source room a move MOVES.
///
/// `participants` is the SFU's own list for the source room;
/// `owner_identity` is the listed connection that is the own seat of the
/// session recorded as owning the participant ([`owner_listed_seat`]), if
/// any; `mapped_identity` is what `voice_identity:{from}` names for the
/// target, if anything. A candidate is a PRIMARY of the target — its
/// identity's user segment is `target_id` and it is not a screen leg (a leg
/// is a helper of its owner and is never the thing that moves). Among
/// candidates, in order:
///
/// 0. the owner's connection, if the SFU lists it as a primary (merge slice
///    F12): the event goes to the owning session only, so the connection it
///    names should be that session's, and only then may the event name it
///    at all (see [`owner_addressing`]);
/// 1. the mapped identity, if the SFU lists it as a primary — the ingress
///    mapping and the SFU agree, which is the ordinary case;
/// 2. else a primary carrying a non-empty `"conn"` nonce, so the event can
///    address exactly that connection;
/// 3. else the most recently joined (`joined_at_ms`) — the newest connection
///    is the one the user is most plausibly looking at;
/// 4. else the lexically smallest identity, so the answer never depends on
///    the order the SFU happened to list them in.
///
/// `None` means the SFU reports no primary of the target in the room, and
/// the move must answer `NotConnected` before writing anything.
///
/// Pure: the list comes from an RPC the unit tests cannot answer, while the
/// choice is the part that was wrong (a stale mapping used to be trusted
/// over the SFU, so the token addressed a connection that was gone).
fn select_move_connection<'a>(
    participants: &'a [ParticipantInfo],
    target_id: &str,
    owner_identity: Option<&str>,
    mapped_identity: Option<&str>,
) -> Option<&'a ParticipantInfo> {
    let primaries = participants.iter().filter(|participant| {
        user_id_from_participant_identity(&participant.identity) == target_id
            && !is_screen_leg(&participant.identity)
    });

    for preferred in [owner_identity, mapped_identity].into_iter().flatten() {
        if let Some(listed) = primaries
            .clone()
            .find(|participant| participant.identity == preferred)
        {
            return Some(listed);
        }
    }

    // `min_by` under an ordering where "preferred" sorts FIRST: a nonce
    // before none, a later join before an earlier one, then the smaller
    // identity. Identities are unique within a room, so the last key never
    // ties and the answer is independent of list order.
    primaries.min_by(|a, b| {
        conn_nonce_of(b)
            .is_some()
            .cmp(&conn_nonce_of(a).is_some())
            .then_with(|| b.joined_at_ms.cmp(&a.joined_at_ms))
            .then_with(|| a.identity.cmp(&b.identity))
    })
}

/// The per-connection nonce a participant's token carried, as the SFU
/// reports it — the `"conn"` attribute minted by `VoiceClient::create_token`.
///
/// Empty is `None`: an empty nonce addresses nothing, and putting one on the
/// wire would let a client with an equally empty attribute read it as a
/// match. Pure, so the empty rule is pinned without an SFU.
fn conn_nonce_of(participant: &ParticipantInfo) -> Option<String> {
    participant
        .attributes
        .get(voice_client::CONN_NONCE_ATTRIBUTE)
        .filter(|nonce| !nonce.is_empty())
        .cloned()
}

/// How a move addresses the connection it moves: both fields of the
/// `UserMoveVoiceChannel` event's addressing gate, and the device the token
/// is minted for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MoveAddressing {
    /// The device suffix of the moving connection's identity: `D` for
    /// `{user}:D`, `None` for a bare `{user}`. Handed to `create_token`, so
    /// the token's identity is exactly the moving connection's.
    device_id: Option<String>,
    /// The moving connection's own `"conn"` nonce, per [`conn_nonce_of`].
    conn_nonce: Option<String>,
}

/// The addressing for moving `moving`, a connection of `target_id`.
///
/// ONE function for both fields, called once with the connection
/// [`select_move_connection`] chose, so the two cannot come from different
/// places. Each could silently drift on its own: a `device_id` taken from the
/// Redis mapping instead of from `moving` addresses a connection the SFU no
/// longer lists, and a `conn_nonce` of `None` switches the client-side nonce
/// gate off on every seat. Neither fails anything; both just address the
/// wrong session or none. Pure, so both rules are pinned by value.
fn move_addressing(moving: &ParticipantInfo, target_id: &str) -> MoveAddressing {
    MoveAddressing {
        device_id: moving
            .identity
            .strip_prefix(&format!("{target_id}:"))
            .map(str::to_string),
        conn_nonce: conn_nonce_of(moving),
    }
}

// ---- who a move is delivered to (media-e2ee final audit F1, merged from
// voice-move into the one move function, merge slice RB-H1) ----

/// The device suffix of a moved participant's LiveKit identity (`user:device`),
/// or `None` when the move takes the bare-identity path.
///
/// With media E2EE switched off, `join_call` admits only bare identities (a
/// device claim is refused `FeatureDisabled` by `require_media_e2ee_enabled`),
/// so a move never mints a device-qualified token then either: it falls back
/// to the bare identity the target could join with themselves.
///
/// An identity ending in `:` yields `Some("")`, which no identity row matches,
/// so it fails closed below rather than being treated as bare.
fn qualified_move_device<'a>(
    identity: &'a str,
    user_id: &str,
    media_e2ee_enabled: bool,
) -> Option<&'a str> {
    if !media_e2ee_enabled {
        return None;
    }

    identity.strip_prefix(user_id)?.strip_prefix(':')
}

/// Where a move's `UserMoveVoiceChannel` event goes, and whether it carries a
/// token. Every delivery reaches ONE session at most: the one that owns the
/// target's participant in the source channel. Never every session of the
/// user.
#[derive(Debug, PartialEq, Eq)]
enum MoveDelivery {
    /// Publish only to `session_id` with a token for `device_id`, or for the
    /// bare identity when `None`. Only that session could have got the same
    /// token from `join_call`.
    Session {
        session_id: String,
        device_id: Option<String>,
    },
    /// Publish only to `session_id`, with no token. The client falls back to
    /// `join_call`, which enforces device binding.
    SessionNoToken { session_id: String },
    /// Publish nothing: no session is known to own the participant (a join
    /// from before the record existed). The move is done as a disconnect:
    /// the target is taken out of the source and nothing else happens.
    Nobody,
}

/// What the move does with a [`MoveDelivery`]: the token it mints and the
/// session it publishes to. The move branches on nothing else.
#[derive(Debug, PartialEq, Eq)]
struct MoveTokenPlan<'a> {
    /// `None`: mint no token. `Some(None)`: mint the bare-identity token.
    /// `Some(Some(device))`: mint the token for `user:device`.
    mint: Option<Option<&'a str>>,
    /// The one session the event is published to, on its `session_topic`
    /// (`EventV1::private_session`, the move's only publish). `None`:
    /// publish nothing, and disconnect instead of moving.
    session: Option<&'a str>,
}

/// Plan the token and topic of a move. A token is minted only for a delivery
/// that reaches exactly one session, and a device-qualified one only for the
/// device that session is bound to.
fn move_token_plan(delivery: &MoveDelivery) -> MoveTokenPlan<'_> {
    match delivery {
        MoveDelivery::Session {
            session_id,
            device_id,
        } => MoveTokenPlan {
            mint: Some(device_id.as_deref()),
            session: Some(session_id.as_str()),
        },
        MoveDelivery::SessionNoToken { session_id } => MoveTokenPlan {
            mint: None,
            session: Some(session_id.as_str()),
        },
        MoveDelivery::Nobody => MoveTokenPlan {
            mint: None,
            session: None,
        },
    }
}

/// Decide the delivery of a move's event.
///
/// `recorded_session` is the session that owns the target's participant in
/// the SOURCE channel (`get_voice_participant_session`): the one whose
/// `join_call` put it there, or that a previous move carried there. It is the
/// only possible recipient. Without it the owner is unknown and nobody gets
/// the event: sent to every session, it would reach a session the owner just
/// kicked with `force_disconnect`, which then rejoins the destination and
/// kicks the owner (media-e2ee final audit F1).
///
/// `seat` is the seat kind recorded with that session at its join
/// ([`SeatKind`], via [`owner_recorded_seat`]), and the move mints EXACTLY
/// that kind of seat (merge slice RRB-1, the operator's ruling 2026-09-28,
/// Option A, which replaced SEC2-3's "bound to any device" rule):
///
/// - [`SeatKind::Bare`]: a bare token, only when the connection the move
///   chose IS the target's bare seat (`bare_seat_chosen`: its identity is
///   the bare user id). It is what the owner is seated as and what
///   `join_call` would hand it too, so the moderator rules (a timeout
///   channel it cannot Connect to, a full channel) and the AFK sweep apply
///   to it like to any bare seat, whatever device its session is bound to.
///   With another seat chosen (the owner's bare seat is not listed, a device
///   seat is), no token (merge slice SEC4-1): the record says bare, but the
///   connection the move addresses and evicts is a device seat, which may
///   be the owner itself connected with a device token since its last
///   `join_call`; a bare token would seat that E2EE client as a bare
///   identity, and would carry the admission key past Connect for a seat
///   the move never chose.
/// - [`SeatKind::Device`]: a token for THAT device, only when it is the device
///   of the connection the move chose (`device`, the result of
///   [`qualified_move_device`], so never with media E2EE off) and the
///   recorded session IS the session `assert_bound_session` accepts for it
///   (`bound_session`, the `last_session_id` of the target's E2EE identity
///   row for `device`, `None` with no row; revoking a device deletes its row,
///   `E2EEIdentity::revoke_device`). A device-qualified token lets its holder
///   act as that device on the SFU. Otherwise (another device's seat chosen,
///   a bare seat chosen, no row, a revoked device, a device re-bound to
///   another session since the join, media E2EE off) the owner is told with
///   no token and joins through `join_call`, which checks the binding
///   itself. Never a bare token: that would seat an E2EE client in the
///   destination as a bare identity instead of as its device. The move
///   reads the binding again right before its owner re-check
///   ([`device_binding_still_holds`], media-e2ee S6M-3).
/// - [`SeatKind::Unknown`] (a record from before the seat kind was
///   recorded): told with no token, the conservative choice.
///
/// An empty session id or device id fails closed.
fn move_event_delivery(
    recorded_session: Option<&str>,
    seat: &SeatKind,
    device: Option<&str>,
    bare_seat_chosen: bool,
    bound_session: Option<&str>,
) -> MoveDelivery {
    let Some(session_id) = recorded_session.filter(|session_id| !session_id.is_empty()) else {
        return MoveDelivery::Nobody;
    };

    match seat {
        SeatKind::Bare if bare_seat_chosen => MoveDelivery::Session {
            session_id: session_id.to_string(),
            device_id: None,
        },
        SeatKind::Device(seated)
            if !seated.is_empty()
                && device == Some(seated.as_str())
                && bound_session == Some(session_id) =>
        {
            MoveDelivery::Session {
                session_id: session_id.to_string(),
                device_id: Some(seated.clone()),
            }
        }
        SeatKind::Bare | SeatKind::Device(_) | SeatKind::Unknown => MoveDelivery::SessionNoToken {
            session_id: session_id.to_string(),
        },
    }
}

/// The seat kind recorded for `owner` in the source (`record`, as
/// [`get_voice_participant_session_seat`] read it inside the move): the
/// record's seat kind only when the record names `owner` itself. A record
/// naming another session (a join since the caller read `owner`), or none,
/// is [`SeatKind::Unknown`]: the carry-over then refuses the move anyway,
/// because the source no longer holds the record it compares. No owner is
/// `Unknown` too. Pure: the read is pinned in the move, this by value.
fn owner_recorded_seat(owner: Option<&str>, record: Option<(String, SeatKind)>) -> SeatKind {
    match (owner, record) {
        (Some(owner), Some((session_id, seat))) if !owner.is_empty() && session_id == owner => seat,
        _ => SeatKind::Unknown,
    }
}

/// Whether a SELF-move may go ahead: only when the request comes from
/// `recorded_session`, the session that owns the user's participant in the
/// source channel (`get_voice_participant_session`). The move itself asks
/// this for `MovePolicy::SelfMove`, before anything but the `AlreadyPresent`
/// and expected-source answers (merge slice SEC2-2), so no caller can skip
/// it; a route may also ask it earlier, before it writes anything.
///
/// The move event goes to that session alone ([`move_event_delivery`]), which
/// obeys it. Any other session of the same user asking would steer the
/// owning session into a channel it never chose: a stolen web session moving
/// the victim's desktop. The device binding (`assert_bound_session`) only
/// covers a device-qualified participant; this covers a bare one too.
///
/// `request_session` is the id of the calling session, or `None` when there
/// is none (a bot) or it belongs to someone else. With no recorded session
/// the owner is unknown and the move is refused, bare or device-qualified:
/// its event would reach nobody ([`MoveDelivery::Nobody`]), so all it could
/// do is kick the caller's own participant. The caller stays in the call and
/// can rejoin, which records the session again. An empty id matches nothing.
pub fn self_move_from_owning_session(
    recorded_session: Option<&str>,
    request_session: Option<&str>,
) -> bool {
    match (recorded_session, request_session) {
        (Some(recorded), Some(request)) => !recorded.is_empty() && recorded == request,
        _ => false,
    }
}

/// The target's E2EE identity row for `device_id`, or `None` if the device is
/// not registered (never was, or was revoked). Other errors propagate.
async fn fetch_device_identity(
    db: &Database,
    user_id: &str,
    device_id: &str,
) -> Result<Option<crate::E2EEIdentity>> {
    match db.fetch_e2ee_identity(user_id, device_id).await {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Whether the device a move minted a token for is STILL bound to the
/// session the move is announced to (media-e2ee S6M-3), as re-read right
/// before the owner re-check: `bound_session` is the `last_session_id` of the
/// target's identity row for that device, `None` with no row (the device
/// revoked). Only an exact match with a non-empty planned session holds; no
/// planned session never does. Pure, so the rule is pinned by value.
fn device_binding_still_holds(planned_session: Option<&str>, bound_session: Option<&str>) -> bool {
    matches!(
        (planned_session, bound_session),
        (Some(planned), Some(bound)) if !planned.is_empty() && planned == bound
    )
}

/// The listed primary of `target_id` that is the OWNER's own seat, per the
/// seat kind recorded with the owner at its join (`seat`,
/// [`owner_recorded_seat`]): the connection the move should prefer, because
/// the event goes to the owner alone (merge slice F12) and the move mints
/// only the recorded seat kind (merge slice RRB-1).
///
/// - [`SeatKind::Device`]: that device's seat (`{target}:{device}`), if
///   listed. Any other device seat, bound to the owner or not, is not the
///   one it joined as.
/// - [`SeatKind::Bare`]: the target's BARE seat, if listed (merge slice
///   M2B-7): the owner's own bare seat beats a sibling's device seat, which
///   it could only be told about without a token.
/// - [`SeatKind::Unknown`], or the recorded seat not listed: `None`, and the
///   ordinary rules decide. The delivery then still mints only the recorded
///   seat kind ([`move_event_delivery`]).
///
/// Legs and other users never count. Pure: the seat kind comes from a read
/// the move makes, which the unit tests pin by value instead.
fn owner_listed_seat(
    participants: &[ParticipantInfo],
    target_id: &str,
    seat: &SeatKind,
) -> Option<String> {
    let seat_identity = match seat {
        SeatKind::Device(device_id) if !device_id.is_empty() => format!("{target_id}:{device_id}"),
        SeatKind::Bare => target_id.to_string(),
        SeatKind::Device(_) | SeatKind::Unknown => return None,
    };

    participants
        .iter()
        .map(|participant| participant.identity.as_str())
        .find(|identity| {
            *identity == seat_identity
                && user_id_from_participant_identity(identity) == target_id
                && !is_screen_leg(identity)
        })
        .map(str::to_string)
}

/// The addressing the move EVENT may carry (merge slice F12, the nonce
/// rule): the chosen connection's `conn_nonce` and `device_id` only when
/// that connection is proven the recorded session's, which is exactly when
/// the plan mints a token for its device (`move_event_delivery` answers
/// `Session` with that device only for the bound session). Otherwise both
/// are omitted and the owning session's client falls back to "am I connected
/// to `from`": naming a connection that is not the owner's would make the
/// owner see a nonce mismatch and drop itself, while the named connection is
/// evicted with no event, and the user would land in no call.
///
/// `device_id` is addressing only (F13): present, it is also the device the
/// token in the same event was minted for.
fn owner_addressing(plan: &MoveTokenPlan, addressing: &MoveAddressing) -> MoveAddressing {
    let proven = matches!(
        (plan.mint, addressing.device_id.as_deref()),
        (Some(Some(minted)), Some(device)) if minted == device
    );

    if proven {
        addressing.clone()
    } else {
        MoveAddressing {
            device_id: None,
            conn_nonce: None,
        }
    }
}

/// Whether the target has left the source channel a caller decided about:
/// `expected_from` names that channel, `from` is what the `{user}:{server}`
/// pointer names now. There is no "no expectation" any more (AFK S-3
/// cleanup): every caller decides about one particular source.
fn source_moved_on(expected_from: &str, from: &str) -> bool {
    expected_from != from
}

/// Move `target` into `destination`, server-authoritatively, for a caller
/// that decided the move about a particular SOURCE channel (Wave 5b-2 audit
/// A2). The only move entry point: the four-argument form that expected no
/// source had no production caller left and was deleted (S-3 RB-1).
///
/// EVERY ARGUMENT IS DAEMON-CONSTRUCTIBLE, AND DELIBERATELY SO. There is no
/// `Member`, no `Server`, no acting user and no Rocket type here:
///
/// - the member document is fetched lazily by the permission query (see
///   `admit_voice_move`), so a caller cannot accidentally hand over a stale
///   one and mint a token from permissions that no longer apply;
/// - `server_id` is derived from `destination.server()` and `None` is a hard
///   `UnknownChannel`. It is NOT a parameter, because a parameter is how a
///   future caller passes `None` and points this at a DM or a Group;
/// - there is no acting user because the AFK sweep does not have one.
///
/// The caller decides whether the move is *allowed by policy* (the route
/// checks `MoveMembers` and ranking; the sweep checks idleness). This decides
/// whether it is *possible and safe*, and returns what it did.
///
/// The AFK sweep decides from an idle claim naming the channel the member was
/// idle in, and the moderator route from the source its gate checked; between
/// that read and this call the member may deliberately switch to another
/// channel of the server. Re-deriving `from` from the pointer alone would move
/// them out of the channel they just chose. So `expected_from` is REQUIRED
/// (AFK S-3 cleanup; it used to be an `Option` whose `None` meant "wherever
/// the pointer says", and no caller passed `None` any more): a pointer that
/// no longer names `expected_from` answers `NotConnected` BEFORE any
/// admission, listing, write or mint. From the caller's point of view the
/// member it meant is no longer connected there. A target already sitting in
/// the destination is answered `AlreadyPresent` ahead of that check (S-3
/// RA-2).
///
/// This narrows the window to the few reads between this check and the SFU
/// listing; it does not close it.
///
/// `expected_session` is the session recorded as owning the target's
/// participant in `expected_from` (`get_voice_participant_session`), read
/// ONCE by the caller (the route uses the same value for its self-move
/// check; the sweep reads it after its re-read). The move is announced to
/// that session alone, with a token only when that session could have
/// minted the same one through `join_call` (merge slice, media-e2ee final
/// audit F1). `None` means nobody can be told: a moderator's move is then
/// done as a disconnect (`VoiceMoveOutcome::Disconnected`); a sweep's is
/// refused (`InvalidOperation`) and a self-move's (`NotAuthenticated`)
/// before any write. `policy` decides the target's admission
/// ([`MovePolicy`]), and for a self-move carries the request's session,
/// which must be `expected_session` itself. There is deliberately no device
/// parameter (R14): the seat kind comes from the source record `join_call`
/// wrote (merge slice RRB-1), the device from the connection the SFU lists,
/// and whether it may be minted for from both and its E2EE binding.
///
/// The order, and why (m1_sec S1-S23): every read, admission and refusal
/// first, including the move's own SFU listing and the delivery decision;
/// then the session carry-over (the first write); then, for an owner only,
/// the destination's node pin and room; ONE remote-control release for
/// either arm; the mint, from the plan only; for a device token, the device
/// binding re-read (media-e2ee S6M-3); the owner re-check, the last read
/// before the publish (media-e2ee S6RM-1); the admission key and the
/// `moved_to` label, for an owner only; the event, on
/// the owner's session topic; the evictions.
pub async fn move_user_to_voice_channel_expecting(
    db: &Database,
    voice_client: &VoiceClient,
    target: &User,
    destination: &Channel,
    expected_from: &str,
    expected_session: Option<&str>,
    policy: MovePolicy<'_>,
) -> Result<VoiceMoveOutcome> {
    // Derived here, never passed in, for the reason in this function's doc
    // comment — and derived BEFORE
    // admission rather than taken out of it, so that the "they are already
    // there" answer below can be given without running any admission work at
    // all. A DM or a Group still cannot reach a line past this point.
    let Some(server_id) = destination.server() else {
        return Err(create_error!(UnknownChannel));
    };

    let Some(from) = get_user_voice_channel_in_server(&target.id, server_id).await? else {
        return Ok(VoiceMoveOutcome::NotConnected);
    };

    // Source == destination: the FIRST answer, ahead of the expected-source
    // check below (S-3 RA-2). A moderator who moves someone to where they
    // already are asked for an end state that already holds, and the route
    // answers `AlreadyPresent` as a 200 no-op. With the expectation checked
    // first, a target who had moved on from the authorized source INTO the
    // destination answered `NotConnected` — a 400 for a move whose result
    // was already true. Both answers are pre-write, so the order changes the
    // answer only, never a side effect; the AFK sweep maps both to the same
    // clear.
    //
    // Without this guard at all, the code below evicts the target from the
    // very room it is putting them back into: every connection of theirs
    // that the SFU lists in `from` goes through
    // `remove_identity_if_present`, and `from` is now also the destination,
    // so the user is kicked out of the call they were already happily in.
    // Harmless-looking on a moderator route (nobody moves someone to where
    // they are), fatal on a timer: the AFK sweep's population is idle members
    // and its destination is where idle members already sit, so every tick
    // would re-kick the entire AFK channel.
    //
    // Decided BEFORE `admit_voice_move`, not after it: a member who is
    // already in the destination must not have to be admissible to it all
    // over again. Sitting in a capped, full AFK channel used to answer
    // `CannotJoinCall` for every occupant on every tick — the caps were asked
    // before anyone asked whether there was anything to do. The cap itself
    // now exempts an occupant as well, because the route's side-effect-free
    // pre-flight reaches the cap without ever reaching this line.
    if from == destination.id() {
        return Ok(VoiceMoveOutcome::AlreadyPresent);
    }

    // The caller's source is gone (see the doc comment): nothing admitted,
    // listed, written or minted. Checked right after the source ==
    // destination guard and before every other step: whatever else is true,
    // the premise the caller decided on no longer holds.
    if source_moved_on(expected_from, &from) {
        return Ok(VoiceMoveOutcome::NotConnected);
    }

    // Whether anybody can be told about this move is known from the
    // caller's record alone, so it is decided here (merge slice P2A-10). An
    // empty id is no owner. `Nobody` still runs admission, the caps and the
    // node checks below, like any move. A SWEEP with no owner is refused
    // right here, before anything is written: the sweep skips such a member
    // itself (ruling 09-27: a delta rolled back below the merge would make
    // every join ownerless, and the AFK sweep must never turn that into
    // mass disconnects), and this is the defense in depth behind it.
    let owner = expected_session.filter(|session_id| !session_id.is_empty());
    if owner.is_none() && policy == MovePolicy::Sweep {
        return Err(create_error!(InvalidOperation));
    }

    // A SELF-move goes ahead only from the session that owns the participant
    // (merge slice SEC2-2, invariant B4), decided HERE so no caller can skip
    // it: after `AlreadyPresent` and the expected-source check (a same-channel
    // self-move from a sibling session stays a no-op, and a source the member
    // left stays `NotConnected`), before admission, the SFU and any write.
    // Any other session of the user asking would steer the owning session
    // into a channel it never chose. With no owner recorded it is refused
    // too, never done as the disconnect a moderator's move becomes.
    if let MovePolicy::SelfMove { request_session } = policy {
        if !self_move_from_owning_session(owner, request_session) {
            return Err(create_error!(NotAuthenticated));
        }
    }

    let VoiceMoveAdmission { permissions } =
        admit_voice_move(db, target, destination, policy).await?;

    let destination_channel = UserVoiceChannel::from_channel(destination);

    assert_call_caps_admit(db, &destination_channel, &target.id).await?;

    // NOT an unwrap. `{user}:{server}` and `node:{channel}` are separate keys
    // with no shared lifetime, so a room that finished or was reconciled away
    // leaves the per-user pointer behind with no node key to match it. As an
    // unwrap that was a 500 on the route and, in crond, a panic that
    // `cron_task_wrapper` catches by sleeping 60s — one stale key taking the
    // whole sweep down, over and over. A pointer with no node means the call
    // is gone, which is exactly `NotConnected`.
    let Some(old_node) = get_channel_node(&from).await? else {
        return Ok(VoiceMoveOutcome::NotConnected);
    };

    // A destination that has no room yet is co-located with the source.
    // Decided here, WRITTEN further down: `set_channel_node` is the first
    // thing this function makes durable, and it used to run two statements
    // ahead of the node resolution that can refuse — so an unknown node left
    // the destination pinned to a node the move then declined to use.
    let existing_node = get_channel_node(destination.id()).await?;
    let new_node = existing_node.clone().unwrap_or_else(|| old_node.clone());

    // Resolved BEFORE anything destructive happens — and now genuinely so.
    // An unknown node has to refuse while the target is still in their
    // original room, with no state written on the way out: resolving it after
    // the eviction would leave them kicked out of one call and holding no way
    // into the other.
    let config = config().await;
    let url = config
        .hosts
        .livekit
        .get(&new_node)
        .ok_or_else(|| create_error!(UnknownNode))?
        .clone();

    // THE SFU'S OWN LIST OF THE SOURCE ROOM, read BEFORE ANYTHING IS WRITTEN.
    //
    // One RPC answers three questions, and each has to be answered against
    // the SFU rather than against Redis:
    //
    // - WHICH CONNECTION MOVES (`select_move_connection`). The identity
    //   mapping is a hash keyed by bare user id — one identity per account —
    //   and it goes stale. Trusting it used to mean: a mapping naming a
    //   device connection that had left, while a bare connection of the same
    //   account was live, minted the token for the departed identity,
    //   addressed the event to it (so the live session ignored it), evicted
    //   the live one and reported `Moved`. The user was dropped from the call
    //   and the moderator was told it worked.
    // - WHICH NONCE ADDRESSES IT (`conn_nonce_of`), carried on the event.
    // - WHICH CONNECTIONS GO (`eviction_targets`), used after the emit.
    //
    // Why before the first WRITE and not merely before the mint:
    // `set_channel_node` pins the destination, and the `moved_to` marker
    // further down relabels the target's next Join for as long as it lives.
    // A move that wrote either and then answered `NotConnected` would leave
    // it standing to mislead unrelated joins.
    //
    // A FAILED LIST FAILS THE MOVE, with nothing written, minted or emitted.
    // It used to fall back to a single mapped removal, and the only reason
    // for that was that the list ran AFTER the emit, when the move could no
    // longer be withdrawn. Here it can be, so the error propagates: the route
    // reports it and a timer sweep retries on its next tick, instead of
    // completing a move that cannot see a second connection.
    //
    // A ROOM THE SFU SAYS DOES NOT EXIST is not a failure, though: it is an
    // answer, and the answer is that nobody is connected to it. The room
    // finished (or was reconciled away) and Redis has not caught up yet.
    // `list_participants_if_present` reports that as `None`, and the move
    // answers `NotConnected`, still before any write. Treating it as an
    // error made every sweep tick against such a pointer a 500 and a Sentry
    // event until the pointer was cleaned up.
    //
    // The mapping is read raw, as a PREFERENCE only: an absent mapping is
    // `None`, never an error, because the list is authoritative and a
    // mapping the ingress has not written yet (or has already cleared) says
    // nothing about which listed connection to move. A Redis failure on that
    // read still errors, before any write, like every read above it.
    let mapped_identity = stored_voice_participant_identity(&from, &target.id).await?;
    let Some(participants) = voice_client
        .list_participants_if_present(&old_node, &from)
        .await?
    else {
        log::info!(
            "voice move of {} from {from}: the SFU has no such room; not connected",
            target.id
        );
        return Ok(VoiceMoveOutcome::NotConnected);
    };

    // Media E2EE decides whether a device seat is minted for as that device
    // (merge slice F9): read here, once, through the one helper that checks
    // both flags, never handed in by a caller.
    let media_e2ee = media_e2ee_enabled().await;

    // The seat the owning session was recorded as joining with (merge slice
    // RRB-1: its device, bare, or unknown), from the source record (one
    // read, before any write), and from it the owner's own listed seat, if
    // any (F12, M2B-7): the one the owner's event may name. The seat kind
    // also decides the only token the owner may get: exactly that kind of
    // seat. The record must name `owner` itself; anything else is unknown,
    // and the carry-over below refuses the move then.
    let owner_seat = owner_recorded_seat(
        owner,
        get_voice_participant_session_seat(&from, &target.id).await?,
    );
    let owner_identity = owner_listed_seat(&participants, &target.id, &owner_seat);

    let Some(moving) = select_move_connection(
        &participants,
        &target.id,
        owner_identity.as_deref(),
        mapped_identity.as_deref(),
    ) else {
        // Redis still has them in `from`; the SFU does not. The connection
        // is gone and its `participant_left` has not landed yet. Nothing to
        // move and nothing written: the same answer as a pointer whose room
        // has no node.
        log::info!(
            "voice move of {} from {from}: the SFU lists no connection of theirs; not connected",
            target.id
        );
        return Ok(VoiceMoveOutcome::NotConnected);
    };

    match mapped_identity.as_deref() {
        Some(mapped) if mapped != moving.identity => log::warn!(
            "voice move of {} from {from}: the identity mapping names {mapped}, which the SFU \
             does not list as a connection of theirs; moving {} instead",
            target.id,
            moving.identity
        ),
        None => log::info!(
            "voice move of {} from {from}: no identity mapping recorded; moving {} as listed \
             by the SFU",
            target.id,
            moving.identity
        ),
        Some(_) => {}
    }

    // Both addressing fields come from the CHOSEN connection, `moving`, and
    // from nothing else — never from the Redis mapping, which is only a
    // preference above. The nonce is `moving`'s SOURCE nonce — never the new
    // token's, which is minted inside `create_token` below. Whether the event
    // may carry them at all is `owner_addressing`'s call, further down.
    let addressing = move_addressing(moving, &target.id);
    // And every connection that has to leave `from`, from the same list.
    let evictions = eviction_targets(
        participants
            .iter()
            .map(|participant| participant.identity.clone()),
        &target.id,
    );

    // WHO IS TOLD, AND WITH WHAT (media-e2ee final audit F1; merge slice F1,
    // S12, RRB-1, SEC4-1). The owner gets exactly the seat kind it was
    // recorded as joining with, and only for the CHOSEN connection: a bare
    // seat a bare token only when the chosen connection is the target's bare
    // seat (`bare_seat_chosen`); a device seat a token for THAT device only
    // when it is the chosen connection's device (qualified only under media
    // E2EE) and bound to the owner; the SAME `device` is looked up for its
    // E2EE binding and handed to the delivery, so the binding checked is the
    // binding of the device a token would be minted for. Any other owner (a
    // bare record with a device seat chosen, a device record with another
    // seat chosen, a seat kind unknown) is told with no token and joins
    // through `join_call`, which checks the binding itself; no owner is told
    // nothing.
    let device = qualified_move_device(&moving.identity, &target.id, media_e2ee);
    let bare_seat_chosen = moving.identity == target.id;
    let identity_row = match device {
        Some(device_id) => fetch_device_identity(db, &target.id, device_id).await?,
        None => None,
    };
    let delivery = move_event_delivery(
        owner,
        &owner_seat,
        device,
        bare_seat_chosen,
        identity_row
            .as_ref()
            .map(|row| row.last_session_id.as_str()),
    );
    let plan = move_token_plan(&delivery);
    let event_addressing = owner_addressing(&plan, &addressing);

    // Merge slice P2A-3 / M2B-1: told with no token, the owner's client must
    // join through `join_call`, so the move asks `join_call`'s OWN admission
    // for the target first: Connect, and the destination's occupancy cap
    // with only the `ManageChannel` exemption (`join_call_occupancy_refuses`;
    // the call caps were asked above for every move). A target it would
    // refuse would be evicted into no call at all, so the move is refused
    // here, before the first write. The roster is read only when there is a
    // cap to hold it to. (A self-move was held to both at admission.)
    let target_may_connect = permissions.has_channel_permission(ChannelPermission::Connect);
    if plan.session.is_some() && plan.mint.is_none() {
        let max_users = destination.voice().and_then(|voice| voice.max_users);
        let roster = match max_users {
            Some(_) => get_voice_channel_members(&destination_channel).await?,
            None => None,
        };
        if !target_may_connect
            || join_call_occupancy_refuses(
                roster.as_deref(),
                max_users,
                permissions.has(ChannelPermission::ManageChannel as u64),
            )
        {
            return Ok(VoiceMoveOutcome::TargetCannotJoin);
        }
    }

    // First write. Everything above this line is side-effect free.
    //
    // The carry-over (lane 6a3): the moving session owns the participant in
    // the destination too, because the moved client may join with the token
    // minted below and never call `join_call`, and the NEXT move of this
    // participant reads the destination's record. Only while the source
    // still names that session: a join from another session since the
    // caller read the record has kicked it, and the destination must not be
    // handed to it. One atomic script (SEC2-1), but it covers the carry
    // alone: the source record can change right after it, so the re-check
    // before the event is what the delivery rests on. The whole record is
    // carried, the seat kind the delivery was planned on included (RRB-1),
    // and only while the source still holds exactly that record.
    if let Some(session_id) = plan.session {
        if !carry_voice_participant_session(
            &from,
            destination.id(),
            &target.id,
            session_id,
            &owner_seat,
        )
        .await?
        {
            log::info!(
                "voice move of {} from {from}: the source no longer names the session the \
                 move was planned for; not moved",
                target.id
            );
            return Ok(VoiceMoveOutcome::NotConnected);
        }
    }

    let source_channel = UserVoiceChannel {
        id: from.clone(),
        server_id: destination_channel.server_id.clone(),
    };

    // The destination is prepared only for a move somebody will be told
    // about. A `Nobody` move is a disconnect: no node pin, no room for a
    // join that will never come.
    if plan.session.is_some() {
        if existing_node.is_none() {
            set_channel_node(destination.id(), &new_node).await?;
        }
        voice_client.create_room(&new_node, destination).await?;
    }

    // Remote-control release hook (plan §1): this path removes participants
    // from the SFU directly, bypassing `remove_user_from_voice_channel`, and
    // additionally re-tokens the target into a DIFFERENT room while any grant
    // stays keyed to the old channel — so it must release explicitly here.
    // ONE release for either arm (merge slice F7): a `Nobody` disconnect
    // takes the participant out of the source just the same.
    //
    // BEFORE the mint, not after it (AFK S-3 WC-1). The release is the last
    // SFU work ahead of the emit: up to four calls (the sharer grant's revoke
    // and ejection, the controller grant's), each bounded by
    // `SFU_CALL_TIMEOUT` but not reliably by the breaker (any answer resets
    // its count, and a slow answer under the timeout never adds to it). Run
    // between the mint and the emit, a degraded node could spend the whole
    // `MOVE_TOKEN_TTL` there and hand the target an expired token: moved
    // nowhere. Run here, nothing between the mint and the emit calls the SFU.
    // The cost, accepted: a mint that fails (the target's Mongo reads) now
    // follows a completed release, so the move fails with the grant already
    // ended. That is the revoke direction, and the move is retried.
    remote_control::release_remote_control_for_user(
        db,
        voice_client,
        &source_channel,
        &target.id,
        "revoked_by_moderator",
        // The participant is still in the old room right now. Nothing below
        // reliably ends that: a removal can fail, and on the reordered path
        // the client may instead tear the old room down itself on its way
        // into the new one. Neither is something a grant may be left waiting
        // on, so revoke actively.
        false,
    )
    .await;

    // Minted from the PLAN and nothing else (merge slice F1, RRB-1):
    // `token_device` is the device the owner was recorded as seated as, only
    // when it is also the chosen connection's device and the owning session
    // is the one that device is bound to; `Some(None)` is a bare token, for
    // an owner recorded as seated bare whose bare seat is the chosen
    // connection; there is no token at all for any other owner, or for
    // nobody. Never
    // `addressing.device_id`: a device-qualified token in the hands of a
    // session the device is not bound to lets it sit in the destination as
    // that device.
    //
    // From here to the emit there is no SFU call at all (WC-1, above): the
    // token's `MOVE_TOKEN_TTL` is spent only on the device binding re-read (a
    // database read, for a device token) and on Redis round trips (the
    // re-check, the admission key, the marker).
    let token = match plan.mint {
        None => None,
        Some(token_device) => Some(
            voice_client
                .create_token(
                    &new_node,
                    db,
                    target,
                    permissions,
                    destination,
                    token_device,
                )
                .await?,
        ),
    };
    let minted_identity = plan
        .mint
        .map(|token_device| move_token_identity(&target.id, token_device));

    // THE DEVICE BINDING RE-READ (media-e2ee S6M-3), immediately BEFORE the
    // owner re-check and for a device token only. The binding the delivery
    // was planned on (`identity_row` above) was read before the carry-over,
    // the destination's room, the remote-control release and the mint, up
    // to five SFU calls ago. A device revoked since (its identity row
    // deleted, `E2EEIdentity::revoke_device`) or re-bound to another session
    // (a newer device claim moves `last_session_id`) would let the token
    // just minted seat a session the device is no longer bound to as that
    // device: refused exactly as the re-check below refuses, `NotConnected`
    // with the token dropped unpublished and nothing announced, marked or
    // evicted. A database read, no SFU call (WC-1). A failed read fails the
    // move before anything is announced. A bare token and a tokenless
    // delivery carry no device binding, so there is nothing to re-read.
    //
    // Before the re-check, never after it (media-e2ee S6RM-1 / S6R-1): after
    // it, this database round trip would sit inside the window the re-check
    // leaves open, in which a `join_call` kick or a disconnect goes unseen,
    // and a read stalled there would widen it. Here, the owner re-check stays
    // the last read before the publish.
    if let Some(Some(token_device)) = plan.mint {
        let bound_session = fetch_device_identity(db, &target.id, token_device)
            .await?
            .map(|row| row.last_session_id);
        if !device_binding_still_holds(plan.session, bound_session.as_deref()) {
            log::info!(
                "voice move of {} from {from}: the device the move minted for is no longer \
                 bound to the owning session; nothing announced",
                target.id
            );
            return Ok(VoiceMoveOutcome::NotConnected);
        }
    }

    // THE OWNER RE-CHECK (lane 6a3, merge slice F4/F5), right before the
    // move is announced and for either arm: the source record must still be
    // the WHOLE record the move was planned for, the session AND the seat
    // kind the carry-over compared (merge slice SEC4-2; `None`: still no
    // owner). A `join_call` from another session since the caller read it
    // (which replaces the record), its `force_disconnect` kick from a join
    // into any channel or a disconnect in `member_edit` (each drops it
    // first, `drop_voice_participant_session`), or a rejoin of the SAME
    // session as another kind of seat (the token minted above is of the old
    // kind), means the participant this move would announce and evict is no
    // longer the one it planned for: refused, with nothing announced, marked or
    // evicted. The carry-over above compares the source only at the moment
    // it carries (atomically, SEC2-1), so THIS is the check the delivery
    // rests on. A Redis read, no SFU call (WC-1), and the LAST read before
    // the publish (the device binding re-read above comes first, media-e2ee
    // S6RM-1). What is left of the window is this read to the publish below:
    // the admission key and the marker, two Redis writes.
    if !voice_participant_record_is(&from, &target.id, plan.session, &owner_seat).await? {
        log::info!(
            "voice move of {} from {from}: the owning session changed under the move; \
             nothing announced",
            target.id
        );
        return Ok(VoiceMoveOutcome::NotConnected);
    }

    match plan.session {
        Some(session_id) => {
            // THE ADMISSION KEY (merge slice P2A-4), for a moderator or sweep
            // move of a target who lacks Connect on the destination: without
            // it the voice-ingress re-check (D-3) evicts the moved connection
            // the moment it joins. It names the exact identity just minted
            // for, and it is the move's one MANDATORY write after the mint:
            // failing it fails the move (see `VoiceMoveOutcome`), where the
            // label below stays best-effort. A tokenless owner without
            // Connect was refused before the first write (P2A-3), so an
            // identity was minted whenever the key is needed.
            if needs_move_admission(policy, target_may_connect) {
                let identity = minted_identity
                    .as_deref()
                    .ok_or_else(|| create_error!(InternalError))?;
                set_move_admission(&target.id, destination.id(), identity).await?;
            }

            // The Join label (Wave 5b-2 M4-a). Written HERE, after the room,
            // the release, the mint and the re-check and immediately before
            // the emit, so a move that fails before the target is sent
            // anything leaves no marker to mislabel their next ordinary join
            // (it used to be written before `create_room` and `create_token`,
            // both behind a `?`). The evictions below can still fail the
            // move, but by then the event is out and the join it labels is
            // the one the move asked for.
            //
            // BEST-EFFORT, no `?`: by now the remote-control grant has been
            // revoked, and the marker only picks `VoiceChannelMove` over
            // `VoiceChannelJoin` for the destination's roster; the source's
            // Leave is published regardless. It admits nothing (the
            // admission key does). Failing the move over it would strand the
            // target with a revoked grant and no token.
            if let Err(error) =
                set_user_moved_to_voice(destination.id(), &source_channel, &target.id).await
            {
                log::warn!(
                    "voice move of {} from {from}: the move marker was not written ({error}); \
                     their join to {} will be announced as a join, not a move",
                    target.id,
                    destination.id()
                );
            }

            // EMITTED BEFORE THE EVICTION, AND THE ORDER IS THE FIX.
            //
            // A removal is a LiveKit `RemoveParticipant`, which puts a `Leave`
            // straight down the client's signaling socket. This event has to travel
            // LiveKit -> delta -> Redis publish -> bonfire -> the client's socket:
            // at least two more hops. Emitting it second therefore guaranteed the
            // client was out of CONNECTED before its own move token arrived, and its
            // addressing gate dropped the move in silence — the member landed
            // nowhere, which is the shipped bug this exists to repair.
            //
            // The failure mode this creates, stated rather than left to be
            // discovered: if the emit succeeds and a removal then fails, the target
            // holds a valid token for the destination and that eviction has not
            // happened. That is acceptable, and strictly better than the inverse. A
            // client can only be in one call, so connecting with the token tears down
            // its own old room, which is what the removal was trying to achieve; the
            // worst case is a stale participant in the source room until that
            // teardown reaches the SFU, and the remote-control grant above has
            // already been revoked actively for exactly this reason. The failure is
            // still returned to the caller, so the route does not claim a clean
            // move. The old order's failure mode was worse and more common: the
            // eviction succeeded, the emit never ran, and the target sat disconnected
            // from everything with no token at all.
            //
            // This does not by itself close the race — the client half of it
            // is an acceptance window for a token that arrives just after a
            // drop from `from`. It removes the GUARANTEED loss and makes the
            // ordinary path work; the window is what covers the reordering
            // being lost to scheduling.
            //
            // ONE SESSION (media-e2ee final audit F1, merge slice F2). The
            // event goes on the owning session's topic and nowhere else:
            // `private` (every session of the user) would hand it, token
            // included, to a session the owner kicked, which then rejoins
            // the destination with its mic live. Pinned by
            // `the_move_event_is_published_only_to_the_planned_session` and
            // the workspace-wide statement scan.
            //
            // The addressing inside it (F12): `conn_nonce` and `device_id`
            // name the chosen connection only when it is proven the owner's
            // (`owner_addressing`); both absent, the owner's client acts
            // when it is connected to `from`. `device_id` is addressing only
            // (F13): when present it is also the device `token` was minted
            // for. `token` absent: the owner is not the session the device
            // is bound to, and joins through `join_call`. `url` is the
            // destination node's public URL, resolved above.
            EventV1::UserMoveVoiceChannel {
                node: new_node.clone(),
                url: Some(url),
                device_id: event_addressing.device_id,
                conn_nonce: event_addressing.conn_nonce,
                from: from.clone(),
                to: destination.id().to_string(),
                token,
            }
            .private_session(session_id.to_string())
            .await;
        }
        // Nobody can be told (no recorded owner): the move is the disconnect
        // it amounts to. The release above ended any remote-control grant,
        // the re-check confirmed there is still no owner to steer, and the
        // evictions below take the participant out of the source. Nothing is
        // prepared, minted, admitted, marked or announced for the
        // destination. Never a sweep move (refused before any write).
        None => {
            log::warn!(
                "voice move of {} from {from} to {}: no session owns the participant; \
                 disconnecting instead",
                target.id,
                destination.id()
            );
        }
    }

    // EVICT EVERY CONNECTION THE TARGET HOLDS IN THE SOURCE, not merely the one
    // the identity mapping happens to name.
    //
    // `voice_identity:{channel}` is a HASH WHOSE FIELD IS THE BARE USER ID —
    // one entry per account, not per connection — and its doc comment justifies
    // that with the MLS delivery service's one-device-per-user rule. That rule
    // binds only ENROLLED seats. LiveKit evicts only on a DUPLICATE identity,
    // and `{user}` and `{user}:{device}` are not duplicates, so two sessions of
    // one account can and do sit in the same room. `raise_if_in_voice` does not
    // stop them either: it reads `vc:{user}`, a set written by voice-ingress
    // from a webhook rather than by the join route, so two joins inside the
    // round-trip window both read an empty set and both mint. Which of the two
    // the hash ends up naming is then decided by webhook ordering, because
    // HSET is last-writer-wins.
    //
    // Evicting only the mapped identity is how a move leaves a live connection
    // behind, and the wreckage is worse than "one stale participant": the
    // `participant_left` for the connection that WAS evicted runs
    // `delete_voice_state` and `delete_voice_participant_identity`, both keyed
    // by user id, so the account vanishes from `vc_members:{from}` entirely
    // while the other connection is still publishing its microphone into the
    // source room. Absent from every roster, and unkickable by a removal that
    // resolved the mapping (the since-deleted `remove_user`): the now-empty
    // mapping gave the bare user id, which no-ops against an SFU that knows a
    // device-qualified one. So the SFU's
    // own participant list is the authority here; Redis cannot be.
    //
    // WHAT THE MOVED USER ACTUALLY LANDS AS. The token above, if any, was
    // minted for exactly ONE identity — the connection `select_move_connection`
    // chose from the SFU's list — and the event just emitted went to the one
    // session that owns it (naming the connection by its nonce when it is
    // proven that session's). So the honest description of
    // this leg is: the chosen connection moves, and every OTHER connection of
    // the same account that the list reported is dropped out of the call
    // rather than moved. That is deliberate. Leaving one behind is the
    // defect; a duplicate connection is one that should never have been
    // admitted, and its user reaches the destination through the front door,
    // which re-mints properly. Only one token exists, so handing every
    // connection its own is not on the table here.
    //
    // The evictions come from the SAME list the moving connection was chosen
    // from, so the two cannot disagree about which connections exist. That
    // includes the moving connection itself: it is removed from `from` like
    // the rest, and normally has already left on the event by the time the
    // removal lands.
    //
    // The outcome below still reports `Moved` and reports it unchanged. Adding
    // an eviction count to it would describe a transport detail no caller can
    // act on, and `Moved`'s meaning — "the target is now in the destination" —
    // is as true of one surviving connection as it ever was. What changed is
    // stated on the variant itself.
    //
    // EVERY eviction is attempted before ANY failure is returned. One
    // connection refusing to go is not a reason to leave the rest connected —
    // leaving one connected is the whole defect — so the loop below never
    // returns early: it records every outcome, and `eviction_result` decides
    // afterwards what they amount to. The caller therefore never hears a
    // clean answer about a move that did not finish evicting.
    let mut outcomes = Vec::with_capacity(evictions.len());

    for eviction in evictions {
        let outcome = voice_client
            .remove_identity_if_present(&old_node, &eviction.identity, &from)
            .await;

        if let Err(error) = &outcome {
            log::warn!(
                "failed to evict {} (a connection of {}, {}) from {from} during a voice move: \
                 {error:?}",
                eviction.identity,
                target.id,
                if eviction.reported {
                    "listed by the SFU, so the move fails"
                } else {
                    "a derived screen leg, so the failure is discarded"
                }
            );
        }

        outcomes.push((eviction, outcome));
    }

    eviction_result(outcomes)?;

    if plan.session.is_none() {
        return Ok(VoiceMoveOutcome::Disconnected);
    }

    Ok(VoiceMoveOutcome::Moved {
        node: new_node,
        from,
    })
}

/// What one member's permission sync amounted to, as the room-wide sync
/// records it (AFK Stage 6 F-A1). Also one channel's outcome in the
/// server-wide sync and in the removal walks (AFK S-3 D-2, D-6).
#[derive(Debug, PartialEq, Eq)]
enum MemberSync<E> {
    /// The new grant reached the SFU, or there was nothing to push for this
    /// member (no voice state and no connection listed, or a role-scoped
    /// sync their roles do not reach).
    Synced,
    /// The member is no longer there to sync: the user or member document
    /// is gone, or the SFU has no such participant (for a channel of the
    /// server-wide sync: its document is gone). Not a failure of the
    /// room-wide sync. Carries the error [`sync_user_voice_permissions`]
    /// has always returned for it, which that single-user entry point still
    /// returns.
    Gone(E),
    /// Anything else.
    Failed(E),
}

/// Sync every item in `items`, in order, and record each outcome: the
/// members of one room ([`sync_voice_permissions`]), or the channels of one
/// server ([`sync_server_voice_permissions`], AFK S-3 D-6). `scope` names
/// the room or server in the log lines.
///
/// The loop has no early exit: the per-item call returns a [`MemberSync`],
/// not a `Result`, so there is no `?` to put on it, and one item's failure
/// is recorded and logged while the rest are still synced.
/// [`member_sync_result`] decides afterwards what the outcomes amount to.
/// Generic over the item and the per-item call so the tests drive THIS loop
/// with a fake one; both callers hand it the real one. There is one loop,
/// not one per caller, so the no-early-exit rule cannot drift between them.
async fn sync_each_member<T, E, F, Fut>(
    scope: &str,
    items: Vec<T>,
    mut sync_one: F,
) -> Vec<MemberSync<E>>
where
    T: Display + Clone,
    E: std::fmt::Debug,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = MemberSync<E>>,
{
    let mut outcomes = Vec::with_capacity(items.len());

    for item in items {
        let outcome = sync_one(item.clone()).await;

        match &outcome {
            MemberSync::Synced => {}
            MemberSync::Gone(_) => {
                log::debug!("permission sync of {scope}: skipped {item}, which is no longer there")
            }
            MemberSync::Failed(error) => log::warn!(
                "permission sync of {scope}: failed for {item}, the remaining ones are still \
                 synced: {error:?}"
            ),
        }

        outcomes.push(outcome);
    }

    outcomes
}

/// What a room-wide sync's outcomes amount to: `Ok` unless some member
/// FAILED, and then the FIRST failure. A member who is [`MemberSync::Gone`]
/// is skipped, not an error. Pure, the `eviction_result` shape.
fn member_sync_result<E>(
    outcomes: impl IntoIterator<Item = MemberSync<E>>,
) -> std::result::Result<(), E> {
    let mut failure = None;

    for outcome in outcomes {
        match outcome {
            MemberSync::Synced | MemberSync::Gone(_) => {}
            MemberSync::Failed(error) => {
                failure.get_or_insert(error);
            }
        }
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Re-sync the LiveKit grant of everyone in `channel`'s room (or, with
/// `role_id`, everyone there holding that role).
///
/// EVERY member is tried (AFK Stage 6 F-A1). This used to `?` out on the first
/// member that failed, and every member after it kept a grant that no longer
/// matched the server: publishing in a channel just designated AFK, or still
/// muted in the one that stopped being AFK. A member who has gone (user or
/// member document deleted, or the SFU reports no such participant) is
/// skipped; any other failure is logged, and the first one is returned once
/// every member has been tried.
///
/// ROSTER-DRIVEN (AFK S-3 D-4): the room is listed at the SFU ONCE, through
/// [`VoiceClient::list_participants_reported`], and every listed identity
/// is grouped under its owning user by [`roster_connections`]. The members
/// synced are `vc_members:{channel}` UNION the users the SFU lists, sorted
/// and deduplicated, and each one's grant goes to EVERY connection the
/// listing names for them. Nothing is resolved through the identity mapping,
/// which holds at most one connection per user. So:
///
/// - a user with a second device in the room gets the new grant on both;
/// - a user the SFU lists who has NO voice state here (a connection left
///   stateless, S-3 F-2) is pushed the grant anyway, with no state written
///   and no roster event: see [`push_user_voice_permissions`];
/// - a user with voice state whom the SFU does not list is gone.
///
/// A failed roster read fails the whole room ONCE, and no member is pushed;
/// it is already ERROR + Sentry inside `list_participants_reported`. Every
/// member with voice state STILL gets their roster flags written first
/// ([`SyncConnections::Unlisted`], S-3 B1-R): the listing's error is
/// returned after the walk, so a designation or role change lands in Redis
/// even while the SFU cannot be read.
/// A room the SFU does not have (`Ok(None)`) is an empty roster: members
/// with voice state are then gone, and nothing is pushed.
///
/// Accepted race, as before: a connection whose token was minted before the
/// caller's write and which joins after this listing is not pushed.
///
/// Callers: `sync_afk_designation_change`, [`sync_server_voice_permissions`]
/// (one call per channel, for the server-scoped routes `roles_delete`,
/// `roles_edit_positions` and the server `permissions_set` /
/// `permissions_set_default`, AFK S-3 D-6), and the channel-scoped routes:
/// the channel `permissions_set` and `permissions_set_default`. (`roles_edit`
/// syncs nothing any more: its body cannot change a voice permission, AFK
/// S-3 F-7.) Each route calls its sync last, after its own write, with `?`:
/// none acts on a partial sync, so trying every member before answering
/// changes nothing for them except that later members are no longer left
/// behind.
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
    let node = node.as_str();

    let members = get_voice_channel_members(&user_voice_channel)
        .await?
        .unwrap_or_default();
    // A failed listing does NOT end the room here (S-3 B1-R): every member
    // with voice state still gets their roster flags written, nothing is
    // pushed, and the listing's error is the room's answer, once, after.
    let (mut roster, listing_error) = match voice_client
        .list_participants_reported(node, channel.id())
        .await
    {
        Ok(listed) => (
            roster_connections(
                listed
                    .unwrap_or_default()
                    .into_iter()
                    .map(|participant| participant.identity),
            ),
            None,
        ),
        Err(error) => (BTreeMap::new(), Some(error)),
    };
    let listing_failed = listing_error.is_some();
    let members: Vec<String> = members
        .into_iter()
        .chain(roster.keys().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let outcomes = sync_each_member(channel.id(), members, move |user_id| {
        let connections = roster.remove(&user_id).unwrap_or_default();
        async move {
            let connections = if listing_failed {
                SyncConnections::Unlisted
            } else {
                SyncConnections::Listed(&connections)
            };
            sync_member_voice_permissions(
                db,
                voice_client,
                node,
                &user_id,
                connections,
                channel,
                server,
                role_id,
            )
            .await
        }
    })
    .await;

    match listing_error {
        Some(error) => Err(error),
        None => member_sync_result(outcomes),
    }
}

/// One member of a room-wide sync, by user id, with the connections the
/// room's ONE listing names for them, classified for [`member_sync_result`].
/// A user id that does not resolve to a user (a roster entry that is not an
/// account, or a deleted one) is gone.
#[allow(clippy::too_many_arguments)]
async fn sync_member_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user_id: &str,
    connections: SyncConnections<'_>,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> MemberSync<revolt_result::Error> {
    let user = match Reference::from_unchecked(user_id).as_user(db).await {
        Ok(user) => user,
        Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
            return MemberSync::Gone(error)
        }
        Err(error) => return MemberSync::Failed(error),
    };

    sync_user_voice_permissions_classified(
        db,
        voice_client,
        node,
        &user,
        connections,
        channel,
        server,
        role_id,
    )
    .await
}

/// Where a permission sync takes one user's SFU connections from (AFK S-3
/// D-4). Either way they come from ONE listing of the room.
#[derive(Debug, Clone, Copy)]
enum SyncConnections<'a> {
    /// The room-wide sync listed the room once for every member; these are
    /// this user's identities from that listing (possibly none).
    Listed(&'a [String]),
    /// The single-user entry point: list the room itself, once, after the
    /// member and role checks (so a user they rule out costs no SFU call)
    /// and after the roster-flag write.
    ListRoom,
    /// The room-wide sync's one listing FAILED (S-3 B1-R): the member's
    /// roster flags are still written, nothing is pushed, and the room
    /// answers the listing's error once, after every member.
    Unlisted,
}

/// Re-sync the LiveKit grant of everyone in every call of `server` (or,
/// with `role_id`, everyone there holding that role), AFK S-3 D-6.
///
/// Every id in `server.channels` is tried, through the same no-early-exit
/// loop as a room's members ([`sync_each_member`]), and
/// [`member_sync_result`] decides: the FIRST failure is returned once every
/// channel was tried. Per channel ([`sync_server_channel_voice_permissions`]):
///
/// - no LiveKit node pinned: no call there, skipped WITHOUT a database read;
/// - the channel document is gone (`NotFound`): skipped;
/// - any other fetch error, or a failed [`sync_voice_permissions`]: failed.
///
/// Each channel is fetched by id, not through `db.fetch_channels`, whose
/// drivers disagree on missing ids. `server` is handed down to every room
/// sync, so it must be the POST-update document the caller just wrote.
pub async fn sync_server_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    server: &Server,
    role_id: Option<&str>,
) -> Result<()> {
    sync_server_channels(server, move |channel_id| async move {
        sync_server_channel_voice_permissions(db, voice_client, server, &channel_id, role_id).await
    })
    .await
}

/// The walk of [`sync_server_voice_permissions`]: every id in
/// `server.channels`, in order, through [`sync_each_member`], then
/// [`member_sync_result`]. Generic over the per-channel call so the tests
/// drive this walk with a fake one.
async fn sync_server_channels<F, Fut>(server: &Server, sync_one: F) -> Result<()>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = MemberSync<revolt_result::Error>>,
{
    let outcomes = sync_each_member(&server.id, server.channels.clone(), sync_one).await;
    member_sync_result(outcomes)
}

/// One channel of [`sync_server_voice_permissions`], classified for
/// [`member_sync_result`]. The node pin is read FIRST: a channel with no
/// call costs one Redis read and no database read.
async fn sync_server_channel_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    server: &Server,
    channel_id: &str,
    role_id: Option<&str>,
) -> MemberSync<revolt_result::Error> {
    match get_channel_node(channel_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return MemberSync::Synced,
        Err(error) => return MemberSync::Failed(error),
    }

    let channel = match db.fetch_channel(channel_id).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
            return MemberSync::Gone(error)
        }
        Err(error) => return MemberSync::Failed(error),
    };

    match sync_voice_permissions(db, voice_client, &channel, Some(server), role_id).await {
        Ok(()) => MemberSync::Synced,
        Err(error) => MemberSync::Failed(error),
    }
}

/// Re-sync voice permissions on BOTH sides of an AFK designation change.
///
/// `Server.afk_channel_id` has five writers. The two ROUTES call this:
/// `server_edit` (the designation is moved or cleared) and `channel_create` (a
/// channel is born designated). The other three deliberately do not:
///
/// - the Discord import worker, which writes the designation in step 5 into a
///   server it created moments ago, before step 6 creates any membership. No
///   member exists yet, so nobody can be in its voice channels and there is
///   no grant to re-sync;
/// - the revision-72 migration (the "afk"-named-channel backfill), which runs
///   at deploy with no `VoiceClient` to sync through. Members already sitting
///   in a backfilled channel keep the grant they were minted until they
///   rejoin; the migration's own comment records that;
/// - `Server::clear_afk_channel_if_pointing_at`, which clears the designation
///   when its channel is deleted (`Channel::delete`, from the
///   `channel_delete` route) or stops being a voice channel (`channel_edit`).
///   Both routes tear that channel's call down right there
///   (`delete_voice_channel` deletes the room), so no room is left whose
///   grants could disagree with the server, and nobody is left sitting in the
///   outgoing channel to unmute. There is no incoming side.
///
/// The enforcement gate reads the designation off the server document, not
/// off any per-participant state. So the moment the pointer moves, everyone
/// already sitting in a room on either side of the move is holding a LiveKit
/// grant that no longer matches the server. Occupants of the OUTGOING channel
/// stay muted at the SFU until some unrelated role edit happens to trigger a
/// sync; occupants of the INCOMING channel keep publishing. Neither heals on
/// its own.
///
/// This lives here rather than beside either route because the two routes are
/// sibling modules - a helper in one imported by the other is how the rule
/// ends up with a preferred owner and a second, divergent copy. It is also the
/// only layer that has both halves already: `sync_voice_permissions` is right
/// above, and `VoiceClient` is re-exported from this module, so both routes
/// already import from here.
///
/// `server` must be the POST-update document. The gate reads
/// `server.afk_channel_id` off the `&Server` passed down, so handing it the
/// updated server re-syncs the outgoing channel's occupants to their ungated
/// source set and the incoming channel's to an empty one in a single pass,
/// with no extra fetches.
///
/// `sync_voice_permissions` early-returns when a channel has no LiveKit node,
/// so calling this on idle channels - which is the common case, and always the
/// case for a just-created one - costs one Redis read per side.
///
/// TWO DELIBERATELY DIFFERENT FAILURE MODES, preserved from the `server_edit`
/// implementation this was factored out of:
///
/// - the OUTGOING channel is resolved here and a resolve failure is SWALLOWED.
///   The stored pointer may already be stale (the channel was deleted, or lost
///   its voice information) and the designation write has already committed,
///   so a channel that will not resolve is skipped rather than turned into a
///   late failure on a write that already succeeded.
/// - the INCOMING channel is passed in already resolved, because both callers
///   validate it BEFORE the write - `server_edit` via
///   `Server::validate_afk_channel`, `channel_create` by having just created
///   it. There is nothing to swallow.
///
/// Sync failures themselves are returned after the write has committed,
/// matching every role and permission route's sync (see
/// [`sync_voice_permissions`] and [`sync_server_voice_permissions`]), but
/// only once BOTH sides have been tried (AFK Stage 6 FU-1): an outgoing
/// failure used to `?` out before the incoming side, leaving the new AFK
/// channel's occupants publishing. Now the outgoing result is recorded, the
/// incoming side always runs, and [`designation_sync_result`] returns the
/// first real error of the two. Within each side, every member is tried
/// first as well (see [`sync_voice_permissions`]).
///
/// Only the OUTGOING side is guarded on the designation having actually
/// MOVED. When it has not moved, the outgoing channel IS the incoming one,
/// and syncing it as "no longer AFK" would be wrong. The INCOMING side always
/// syncs, so an admin who re-sends the same `afk_channel_id` walks the room
/// again (AFK Stage 6 F-A1). That is the heal path after a sync that failed
/// for some members: before every member was tried, a re-send was a no-op
/// and the members left behind stayed publishing in the AFK channel.
///
/// `role_id: None` on both calls means every member currently in the room,
/// which is what a server-level designation change affects - it is not scoped
/// to a role the way the two `permissions_set` syncs are.
pub async fn sync_afk_designation_change(
    db: &Database,
    voice_client: &VoiceClient,
    server: &Server,
    previous_afk_channel_id: Option<&str>,
    incoming_afk_channel: Option<&Channel>,
) -> Result<()> {
    // Each side's result, recorded rather than `?`-returned, so that an
    // outgoing failure never skips the incoming side (FU-1).
    let mut sides = Vec::with_capacity(2);

    // Outgoing - the channel that is no longer AFK. Resolve-then-check.
    if let Some(previous) = previous_afk_channel_id {
        if server.afk_channel_id.as_deref() != Some(previous) {
            if let Ok(channel) = db.fetch_channel(previous).await {
                let outgoing =
                    sync_voice_permissions(db, voice_client, &channel, Some(server), None).await;
                if let Err(error) = &outgoing {
                    log::warn!(
                        "AFK designation change on {}: the outgoing channel {previous} did not \
                         fully re-sync, the incoming side still runs: {error:?}",
                        server.id
                    );
                }
                sides.push(outgoing);
            }
        }
    }

    // Incoming - already resolved and validated by the caller. Unguarded, so
    // a re-send of the same designation re-syncs (see the doc comment).
    if let Some(channel) = incoming_afk_channel {
        sides.push(sync_voice_permissions(db, voice_client, channel, Some(server), None).await);
    }

    designation_sync_result(sides)
}

/// What the two sides of a designation change amount to: `Ok` when every
/// side that ran succeeded, else the FIRST error, the outgoing side's when
/// both failed. Pure, and the same rule as [`member_sync_result`], which it
/// delegates to so the two cannot drift.
fn designation_sync_result<E>(
    sides: impl IntoIterator<Item = std::result::Result<(), E>>,
) -> std::result::Result<(), E> {
    member_sync_result(sides.into_iter().map(|side| match side {
        Ok(()) => MemberSync::Synced,
        Err(error) => MemberSync::Failed(error),
    }))
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

/// The baseline a permission sync's roster update is compared against: a
/// `PartialUserVoiceState` carrying nothing but the participant's id.
///
/// `sync_user_voice_permissions` fans out only `if update_event != before`,
/// so this value is what "nothing changed, emit nothing" literally means.
/// It is a named function rather than an inline literal so that the
/// regression test for [`roster_flags`] can compare against the SAME
/// baseline the production guard uses instead of re-typing it.
pub(crate) fn roster_baseline(user_id: &str) -> PartialUserVoiceState {
    PartialUserVoiceState {
        id: Some(user_id.to_string()),
        ..Default::default()
    }
}

/// The roster half of a permission sync: given the participant's CURRENT
/// voice state and the source list the AFK gate has already been applied to,
/// produce the `PartialUserVoiceState` to persist and fan out.
///
/// Audit MEDIUM-7, and the remediation of audit HIGH-1 on that fix.
///
/// `can_video` / `can_speak` are DERIVED FROM THE GATED SOURCE LIST rather
/// than recomputed from permission bits, and that is load-bearing, not
/// tidiness. D2 deliberately puts AFK outside the permission system, so under
/// an AFK designation the bits are unchanged; recomputing from them would
/// leave every field `None`, `update_event == before` would hold and the
/// fan-out would emit NOTHING. The SFU would kill the tracks while every
/// other client kept rendering a camera tile and a speaking indicator for
/// someone now silent and dark, until an unrelated resync happened.
///
/// Reading them off `allowed_sources` cannot drift from the gate: the list
/// contains `Camera` iff (Video permission && video limit) and `Microphone`
/// iff Speak — exactly the two expressions this replaced — and is EMPTY under
/// AFK, which forces `camera` / `screensharing` / `screen_video` /
/// `is_publishing` to `Some(false)` for anyone who currently has them set and
/// so makes the roster update.
///
/// This lives in a function called by BOTH `sync_user_voice_permissions` and
/// its regression test on purpose. The previous test re-typed these four
/// expressions, so reverting the production derivation to the permission-bit
/// form left it green — the defect it is named for would have shipped.
///
/// `recording` is DELIBERATELY absent, unlike every flag above and unlike the
/// remote-control teardown. Revoking `RecordCall` mid-call cannot stop a
/// recording that is already running: the recorder is a MediaRecorder in the
/// participant's own client, holding tracks it has already been sent, and no
/// server-asserted state reaches it. Clearing the flag would therefore not end
/// the recording — it would only delete the indicator that says one is
/// happening, leaving everyone else in the call believing they are unrecorded
/// while the file keeps growing. A stale-true flag over-warns; a cleared one
/// lies. This is the opposite direction from remote control (where the server
/// genuinely holds the capability and revoking it genuinely ends the session)
/// and the asymmetry is the whole point: revoke the bit to stop the NEXT
/// recording.
pub(crate) fn roster_flags(
    user_id: &str,
    allowed_sources: &[TrackSource],
    state: &UserVoiceState,
) -> PartialUserVoiceState {
    let can_video = allowed_sources.contains(&TrackSource::Camera);
    let can_speak = allowed_sources.contains(&TrackSource::Microphone);

    PartialUserVoiceState {
        camera: state.camera.then_some(can_video),
        screensharing: state.screensharing.then_some(can_video),
        screen_video: state.screen_video.then_some(can_video),
        is_publishing: state.is_publishing.then_some(can_speak),
        ..roster_baseline(user_id)
    }
}

#[cfg(test)]
mod permission_tests {
    use livekit_protocol::TrackSource;
    use revolt_config::FeaturesLimits;
    use revolt_permissions::{ChannelPermission, PermissionValue};

    use super::{
        get_allowed_sources, roster_baseline, roster_flags, user_id_from_participant_identity,
        voice_participant_permissions, AfkGate, Timestamp, UserVoiceState,
    };

    /// A resolved "this is not the AFK channel" gate, for the tests that are
    /// about something other than AFK.
    fn not_afk() -> AfkGate {
        AfkGate::from_raw_for_tests(false)
    }

    /// A resolved "this IS the AFK channel" gate.
    fn afk() -> AfkGate {
        AfkGate::from_raw_for_tests(true)
    }

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

    // ---- the voice-move eviction filter ----
    //
    // WHAT THESE CANNOT COVER. The filter's input is a LiveKit
    // `ListParticipants` response and its output is a sequence of
    // `RemoveParticipant` calls, neither of which exists on a build box with no
    // SFU; the delta route harness that would drive the move end to end needs
    // RabbitMQ and cannot boot here either. So the RPC round trip itself — that
    // the SFU really does report two connections for one account, and really
    // does honor the removals — is NOT proven by anything below and has to be
    // proven on a live leg.
    //
    // What IS proven is the whole of the decision: given a participant list,
    // exactly which identities get removed and in what order. That is the part
    // that was wrong.

    /// Two connections of one account — a bare identity and a device-qualified
    /// one — are the same user to the filter, which is the property the fix
    /// rests on. To LiveKit they are not duplicates, which is how they came to
    /// be in the room together.
    #[test]
    fn eviction_targets_group_a_bare_and_a_device_qualified_connection() {
        use super::{eviction_targets, is_screen_leg};

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let device = "4208aa7e9ff58761b2d7a5d6c45f7383";
        let qualified = format!("{user}:{device}");

        let evicted: Vec<String> = eviction_targets([user.to_string(), qualified.clone()], user)
            .into_iter()
            // The derived legs have their own test; here we are asking about the
            // primaries.
            .filter(|target| !is_screen_leg(&target.identity))
            .map(|target| target.identity)
            .collect();

        assert_eq!(
            evicted,
            vec![user.to_string(), qualified],
            "both connections of one account must be evicted — evicting only \
             the one the identity mapping names is the defect"
        );
    }

    /// Screen legs. Every primary contributes a DERIVED leg (best-effort,
    /// because a leg that joined after the listing is not in it); a leg the SFU
    /// reported is evicted on its own account and never treated as a primary,
    /// so no fourth-segment identity is ever issued; and a leg always precedes
    /// its owner, because tearing the owner down first orphans it.
    #[test]
    fn eviction_targets_take_every_leg_and_never_derive_a_leg_from_a_leg() {
        use super::eviction_targets;

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let device = "4208aa7e9ff58761b2d7a5d6c45f7383";
        let qualified = format!("{user}:{device}");
        let bare_leg = format!("{user}::screen");
        let qualified_leg = format!("{qualified}:screen");

        // The SFU reports the bare primary's leg but not the qualified one's.
        let evicted = eviction_targets(
            [bare_leg.clone(), user.to_string(), qualified.clone()],
            user,
        );

        let identities: Vec<String> = evicted
            .iter()
            .map(|target| target.identity.clone())
            .collect();
        assert_eq!(
            identities,
            vec![
                bare_leg.clone(),
                user.to_string(),
                qualified_leg.clone(),
                qualified.clone(),
            ],
            "each leg must be evicted immediately before the primary that owns \
             it, and a reported leg must not be re-derived into a fourth segment"
        );

        for target in &evicted {
            assert!(
                !target.identity.contains("screen:screen")
                    && target.identity.matches("screen").count() <= 1,
                "a leg was derived from a leg: {} names a participant the SFU \
                 has never heard of, so the real leg would stay up",
                target.identity
            );
        }

        // A reported identity is a connection the SFU has just named, so its
        // removal failing is a real failure; a derived one is speculative.
        let reported: Vec<(String, bool)> = evicted
            .iter()
            .map(|target| (target.identity.clone(), target.reported))
            .collect();
        assert_eq!(
            reported,
            vec![
                (bare_leg, true),
                (user.to_string(), true),
                (qualified_leg, false),
                (qualified, true),
            ],
            "only the derived leg may be best-effort — discarding the failure \
             of a removal the SFU said was needed is how a ghost survives"
        );
    }

    /// The filter is scoped to ONE account. A different user in the same room
    /// is untouched even when their id shares a prefix with the target's: the
    /// comparison is on the whole first segment, never a prefix, and a move
    /// that ejected a bystander would be a far louder bug than the one being
    /// fixed.
    #[test]
    fn eviction_targets_are_scoped_to_the_one_user() {
        use super::eviction_targets;

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let other = "01KX7HASD9FHBYA3XGKA5YACYZ";
        // Not a real ULID; it is here precisely because it is a prefix of the
        // target's id, which is what a `starts_with` comparison would swallow.
        let prefix = "01KX7HASD9FHBYA3XGKA5YACY";

        let evicted = eviction_targets(
            [
                user.to_string(),
                other.to_string(),
                format!("{other}:4208aa7e9ff58761b2d7a5d6c45f7383"),
                format!("{other}::screen"),
                prefix.to_string(),
            ],
            user,
        );

        assert_eq!(
            evicted
                .iter()
                .map(|target| target.identity.clone())
                .collect::<Vec<String>>(),
            vec![format!("{user}::screen"), user.to_string()],
            "only the target's own connections, and its derived leg, may be \
             evicted"
        );

        // And nothing at all is selected for a user who is not in the room.
        assert!(
            eviction_targets([other.to_string()], user).is_empty(),
            "a listing with no connection of the target selects nothing"
        );
    }

    /// A reported leg listed AFTER its owner: the owner's pass derives the
    /// leg first (best-effort), and the SFU's own report of it must then
    /// upgrade it to REPORTED. The sibling test lists the leg first, which
    /// can never tell whether the upgrade happens at all.
    #[test]
    fn eviction_targets_upgrade_a_derived_leg_the_sfu_also_reported() {
        use super::eviction_targets;

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let leg = format!("{user}::screen");

        let evicted: Vec<(String, bool)> = eviction_targets([user.to_string(), leg.clone()], user)
            .into_iter()
            .map(|target| (target.identity, target.reported))
            .collect();

        assert_eq!(
            evicted,
            vec![(leg, true), (user.to_string(), true)],
            "the SFU reported this leg, so failing to remove it is a real \
             failure — the order it arrived in must not downgrade it"
        );
    }

    /// A REAL prefix: the target's id is a proper prefix of a bystander's.
    /// A `starts_with` comparison would select the bystander; the whole
    /// first segment must match instead.
    #[test]
    fn eviction_targets_do_not_take_a_user_whose_id_extends_the_target() {
        use super::eviction_targets;

        // Not a real ULID — it is here because it is a prefix of `other`.
        let user = "01KX7HASD9FHBYA3XGKA5YACY";
        let other = "01KX7HASD9FHBYA3XGKA5YACYX";

        let evicted: Vec<String> = eviction_targets(
            [
                other.to_string(),
                format!("{other}:4208aa7e9ff58761b2d7a5d6c45f7383"),
                format!("{other}::screen"),
                user.to_string(),
            ],
            user,
        )
        .into_iter()
        .map(|target| target.identity)
        .collect();

        assert_eq!(
            evicted,
            vec![format!("{user}::screen"), user.to_string()],
            "a user whose id merely starts with the target's is a bystander"
        );
    }

    // ---- choosing which connection a move MOVES, and its nonce ----

    /// A participant as the SFU would list it. The nonce attribute is set
    /// under the string LITERAL `"conn"`, never the constant, so drifting
    /// the constant reddens here (the client matches the literal too).
    fn listed(identity: &str, joined_at_ms: i64, nonce: Option<&str>) -> super::ParticipantInfo {
        super::ParticipantInfo {
            identity: identity.to_string(),
            joined_at_ms,
            attributes: nonce
                .map(|nonce| [("conn".to_string(), nonce.to_string())].into())
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    /// The selection with no owner-bound connection (F12 has its own test),
    /// which is the whole of it before the merge slice.
    fn chosen(
        participants: &[super::ParticipantInfo],
        target: &str,
        mapped: Option<&str>,
    ) -> Option<String> {
        super::select_move_connection(participants, target, None, mapped)
            .map(|participant| participant.identity.clone())
    }

    /// Merge slice F12: the connection bound to the owning session wins over
    /// the mapping and over every other rule, when the SFU lists it as a
    /// primary; unlisted (or a leg's identity), it is ignored and the old
    /// order decides.
    #[test]
    fn move_selection_prefers_the_owner_bound_connection() {
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let owned = format!("{user}:D1");
        let other = format!("{user}:D2");
        let participants = [
            listed(&other, 3_000, Some("N-D2")),
            listed(&owned, 1_000, None),
            listed(user, 2_000, Some("N-BARE")),
        ];
        let pick = |owner: Option<&str>, mapped: Option<&str>| {
            super::select_move_connection(&participants, user, owner, mapped)
                .map(|participant| participant.identity.clone())
        };

        assert_eq!(
            pick(Some(&owned), Some(&other)).as_deref(),
            Some(owned.as_str()),
            "the owner's connection beats the mapping"
        );
        assert_eq!(
            pick(Some(&format!("{user}:GONE")), Some(&other)).as_deref(),
            Some(other.as_str()),
            "an owner connection the SFU does not list falls back to the mapping"
        );
        assert_eq!(
            pick(Some(&format!("{owned}:screen")), None).as_deref(),
            Some(other.as_str()),
            "a leg is never chosen, owner or not: the nonce, then the newest join"
        );
    }

    /// The mapped identity wins when the SFU lists it — even listed second,
    /// and even though every other rule would pick the other connection
    /// (it has a nonce and joined later; the mapped one has neither).
    #[test]
    fn move_selection_prefers_the_mapped_identity_when_listed() {
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let device = format!("{user}:D1");
        let participants = [
            listed(user, 2_000, Some("N-BARE")),
            listed(&device, 1_000, None),
        ];

        assert_eq!(
            chosen(&participants, user, Some(&device)).as_deref(),
            Some(device.as_str()),
            "the ingress mapping agrees with the SFU here — trust it"
        );
    }

    /// A screen leg is never the connection that moves: not when it is
    /// listed before its owner, not when it is the most attractive by every
    /// ranking rule, and not even when the mapping names it.
    #[test]
    fn move_selection_never_chooses_a_screen_leg() {
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let device = format!("{user}:D1");
        let leg = format!("{device}:screen");
        let participants = [
            listed(&leg, 9_000, Some("N-LEG")),
            listed(&device, 1_000, None),
        ];

        assert_eq!(
            chosen(&participants, user, None).as_deref(),
            Some(device.as_str())
        );
        assert_eq!(
            chosen(&participants, user, Some(&leg)).as_deref(),
            Some(device.as_str()),
            "a mapping that names a leg is not a primary"
        );
    }

    /// No primary of the target in the list: nothing to move. Legs of the
    /// target and connections of other users do not count.
    #[test]
    fn move_selection_without_a_primary_is_none() {
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let other = "01KX7HASD9FHBYA3XGKA5YACYZ";

        assert_eq!(chosen(&[], user, None), None);
        assert_eq!(
            chosen(
                &[
                    listed(&format!("{user}::screen"), 5_000, Some("N-LEG")),
                    listed(other, 6_000, Some("N-OTHER")),
                    listed(&format!("{other}:D9"), 7_000, Some("N-OTHER-2")),
                ],
                user,
                Some(user),
            ),
            None,
            "only a primary of the target may be moved"
        );
    }

    /// Mapping absent from the list (stale: D1 has gone): fall back to the
    /// primary that carries a non-empty nonce — an EMPTY nonce addresses
    /// nothing, so it ranks with "none", even when it joined last.
    #[test]
    fn move_selection_falls_back_to_the_primary_with_a_nonce() {
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let stale = format!("{user}:D1");
        let participants = [
            listed(&format!("{user}:D2"), 9_000, Some("")),
            listed(user, 1_000, Some("N-BARE")),
            listed(&format!("{user}:D3"), 8_000, None),
        ];

        assert_eq!(
            chosen(&participants, user, Some(&stale)).as_deref(),
            Some(user),
            "a stale mapping must not be trusted over the SFU"
        );
        assert_eq!(chosen(&participants, user, None).as_deref(), Some(user));
    }

    /// Ties on the nonce rule: the most recent join wins, then the lexically
    /// smallest identity — and neither answer depends on list order.
    #[test]
    fn move_selection_tie_breaks_by_join_time_then_identity() {
        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let a = format!("{user}:A");
        let b = format!("{user}:B");

        let by_join = [listed(&a, 1_000, Some("N1")), listed(&b, 2_000, Some("N2"))];
        assert_eq!(chosen(&by_join, user, None).as_deref(), Some(b.as_str()));
        let mut reversed = by_join.clone();
        reversed.reverse();
        assert_eq!(chosen(&reversed, user, None).as_deref(), Some(b.as_str()));

        let by_identity = [listed(&b, 1_000, None), listed(&a, 1_000, None)];
        assert_eq!(
            chosen(&by_identity, user, None).as_deref(),
            Some(a.as_str())
        );
        let mut reversed = by_identity.clone();
        reversed.reverse();
        assert_eq!(chosen(&reversed, user, None).as_deref(), Some(a.as_str()));
    }

    /// The nonce read off a listed participant: absent or EMPTY is `None`,
    /// present is its value. Set under the literal `"conn"` by `listed`.
    #[test]
    fn conn_nonce_of_reads_the_conn_attribute_and_treats_empty_as_none() {
        use super::conn_nonce_of;

        assert_eq!(
            conn_nonce_of(&listed("u", 0, Some("V1StGXR8_Z5jdHi6B-myT"))).as_deref(),
            Some("V1StGXR8_Z5jdHi6B-myT")
        );
        assert_eq!(
            conn_nonce_of(&listed("u", 0, Some(""))),
            None,
            "an empty nonce addresses nothing and must never reach the wire"
        );
        assert_eq!(conn_nonce_of(&listed("u", 0, None)), None);

        // Another attribute is not the nonce.
        let mut other = listed("u", 0, None);
        other
            .attributes
            .insert("leg".to_string(), "screen".to_string());
        assert_eq!(conn_nonce_of(&other), None);
    }

    /// The voice move's body as SHIPPING code: the braced body, with comment
    /// lines dropped so prose that names a call can never satisfy (or trip)
    /// an ordering assertion.
    ///
    /// The body lives in `move_user_to_voice_channel_expecting` (Wave 5b-2
    /// A2), the only move entry point since the four-argument delegating form
    /// was deleted (S-3 RB-1). Every pin that reads this therefore reads the
    /// one body every move runs.
    fn move_body_code() -> String {
        const FILE: &str = "core/database/src/voice/mod.rs";
        const DEFINITION: &str = "pub async fn move_user_to_voice_channel_expecting(";

        let sources = shipping_sources();
        let shipping = &sources
            .iter()
            .find(|(rel, _)| rel == FILE)
            .expect("this very file is not in the workspace scan")
            .1;

        let definition = shipping
            .find(DEFINITION)
            .unwrap_or_else(|| panic!("{FILE} no longer defines `{DEFINITION}`"));
        // Escaped brace: see `both_voice_state_teardowns_clear_the_identity_mapping`.
        let open = definition
            + shipping[definition..]
                .find('\u{7b}')
                .expect("the move has a body");

        braced_body(shipping, open)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn first(body: &str, needle: &str) -> usize {
        body.find(needle)
            .unwrap_or_else(|| panic!("the voice move no longer calls `{needle}`"))
    }

    /// P-3: the SFU listing precedes EVERY write and the mint. A listing
    /// after `set_channel_node` or the `moved_to` marker would let a
    /// `NotConnected` (or a failed list) leave them standing, the marker to
    /// relabel the target's next Join; after the mint, a stale mapping would
    /// address the token to a connection that is gone. The session carry-over
    /// is the move's FIRST write (merge slice P2A-11): a carry ahead of the
    /// listing would hand the destination's record to a move that then
    /// answers `NotConnected`.
    #[test]
    fn the_move_lists_the_source_room_before_any_write() {
        let body = move_body_code();
        let list = first(&body, "list_participants_if_present(");

        for write in [
            "carry_voice_participant_session(",
            "set_channel_node(",
            "set_user_moved_to_voice(",
            "create_room(",
            ".create_token(",
        ] {
            assert!(
                list < first(&body, write),
                "`list_participants_if_present(` must precede `{write}` in \
                 the voice move — a refusal, a gone room or a \
                 failed listing has to leave nothing written and nothing minted"
            );
        }
    }

    /// M4-a (Wave 5b-2): the `moved_to` marker is written after the mint and
    /// after the remote-control release, and before the emit, and nothing
    /// between the write and the emit can fail the move. Each mutation this
    /// catches compiles and ships green otherwise:
    ///
    /// - the write moved back above `.create_token(` (or above the release):
    ///   a mint that fails leaves a marker that relabels the target's next
    ///   ordinary join as a move, for 10 s;
    /// - a `?` on the write (`.await?;`): a Redis hiccup fails a move whose
    ///   remote-control grant has already been revoked, with no token sent.
    #[test]
    fn the_move_marks_the_join_after_the_mint_and_before_the_emit() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        assert_eq!(
            flat.matches("set_user_moved_to_voice(").count(),
            1,
            "the move must write its marker exactly once"
        );
        let marker = first(&flat, "set_user_moved_to_voice(");
        let emit = first(&flat, ".private_session(");

        assert!(
            first(&flat, ".create_token(") < marker,
            "the marker must be written AFTER `.create_token(`"
        );
        assert!(
            first(&flat, "release_remote_control_for_user(") < marker,
            "the marker must be written AFTER the remote-control release"
        );
        assert!(
            marker < first(&flat, "EventV1::UserMoveVoiceChannel") && marker < emit,
            "the marker must be written BEFORE the move event is emitted"
        );

        let window = &flat[marker..emit];
        assert!(
            !window.contains('?'),
            "nothing between the marker write and the emit may carry a `?` — \
             the write is best-effort: {window}"
        );
        assert!(
            window.starts_with(
                "set_user_moved_to_voice(destination.id(), &source_channel, &target.id).await \
                 \u{7b}"
            ),
            "the marker names the destination and the SOURCE channel, and its \
             result is inspected, not propagated: {window}"
        );
    }

    /// AFK S-3 WC-1: the move mints its token AFTER the remote-control
    /// release, so nothing between the mint and the emit calls the SFU. The
    /// release makes up to four SFU calls, each bounded by `SFU_CALL_TIMEOUT`
    /// but not reliably by the breaker (any answer resets it); between the
    /// mint and the emit they could outlast `MOVE_TOKEN_TTL` and hand the
    /// target an expired token. Mutations: the mint moved back above the
    /// release; any `voice_client.` or `remote_control::` call put between
    /// the mint and the emit.
    #[test]
    fn the_move_mints_after_the_release_with_no_sfu_call_before_the_emit() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        assert_eq!(flat.matches(".create_token(").count(), 1, "{flat}");
        assert_eq!(
            flat.matches("release_remote_control_for_user(").count(),
            1,
            "{flat}"
        );
        let mint = first(&flat, ".create_token(");
        let emit = first(&flat, ".private_session(");
        assert!(
            first(&flat, "release_remote_control_for_user(") < mint,
            "the release must run BEFORE the mint: {flat}"
        );
        assert!(mint < emit, "{flat}");

        // Squeezed, so a call chained onto the next line (`voice_client`
        // then `.remove_...`) still reads `voice_client.`.
        let window: String = flat[mint..emit].split_whitespace().collect();
        for banned in ["voice_client.", "remote_control::"] {
            assert!(
                !window.contains(banned),
                "nothing between the mint and the emit may call the SFU (`{banned}`): {window}"
            );
        }
    }

    /// I-19 (Wave 5b-2): the move itself has no bot check. Bots can be in
    /// voice and a moderator may move one; the AFK route refuses bots and the
    /// sweep skips them, each at its own layer. A bot check here would make
    /// the moderator route refuse a move it allows today.
    #[test]
    fn the_move_does_not_look_at_bots() {
        let body = move_body_code();

        assert!(
            !body.contains(".bot"),
            "the voice move reads `.bot` — the bot policy \
             belongs to its callers, not to the move"
        );
    }

    /// A2 (5b-2.1 audit): the expectation, by value. It refuses exactly when
    /// the pointer names some other channel. (The S-3 cleanup made the
    /// expectation required, so the old "no expectation never refuses" case
    /// no longer exists to be asked.)
    #[test]
    fn a_move_expecting_a_source_refuses_only_when_the_pointer_left_it() {
        use super::source_moved_on;

        assert!(!source_moved_on("A", "A"), "still in the source");
        assert!(source_moved_on("A", "B"), "moved on to another channel");
    }

    /// A2 (5b-2.1 audit), INVERTED by S-3 RA-2: the expectation is checked
    /// right after the source == destination guard and BEFORE everything
    /// else the move does, so a member who moved on is answered
    /// `NotConnected` with nothing admitted, listed, written, minted or
    /// emitted — while a target already sitting in the destination is
    /// answered `AlreadyPresent` first, whatever the expectation says. It
    /// used to pin the check ABOVE the guard, which made a moderator's move
    /// of a target already in the destination a 400. Mutations: the check
    /// deleted, its `return` changed, the check moved back above the guard,
    /// or moved below admission, the listing or any write.
    #[test]
    fn the_move_checks_its_expected_source_right_after_already_present() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        const CHECK: &str = "if source_moved_on(expected_from, &from) \u{7b} \
                             return Ok(VoiceMoveOutcome::NotConnected); \u{7d}";
        const GUARD: &str = "if from == destination.id() \u{7b} \
                             return Ok(VoiceMoveOutcome::AlreadyPresent); \u{7d}";
        assert_eq!(
            flat.matches(CHECK).count(),
            1,
            "the move must check its expected source exactly once, answering \
             `NotConnected`: {flat}"
        );
        assert_eq!(
            flat.matches(GUARD).count(),
            1,
            "the move must answer `AlreadyPresent` exactly once: {flat}"
        );
        let check = first(&flat, CHECK);
        let guard = first(&flat, GUARD);

        assert!(
            first(&flat, "let Some(from) = get_user_voice_channel_in_server(") < guard,
            "the guard compares against the pointer, so it follows the read"
        );
        assert!(
            guard < check,
            "RA-2: `AlreadyPresent` must be answered BEFORE the expected-source \
             check, or a target already in the destination is a 400"
        );
        assert_eq!(
            flat[guard + GUARD.len()..check].trim(),
            "",
            "nothing may run between the guard and the expected-source check"
        );
        for later in [
            "admit_voice_move(",
            "list_participants_if_present(",
            "get_voice_participant_session_seat(",
            "fetch_device_identity(",
            "carry_voice_participant_session(",
            "set_channel_node(",
            "create_room(",
            ".create_token(",
            "release_remote_control_for_user(",
            "voice_participant_record_is(",
            "set_user_moved_to_voice(",
            ".private_session(",
            "remove_identity_if_present(",
        ] {
            assert!(
                check < first(&flat, later),
                "the expected-source check must precede `{later}`"
            );
        }
    }

    /// B10 (5b-2.1 audit): the move marker's lifetime is a named constant, at
    /// 10 s, and it is what `set_user_moved_to_voice` actually passes. The AFK
    /// sweep asserts its claim TTL against this constant.
    #[test]
    fn the_move_marker_lives_ten_seconds() {
        assert_eq!(super::MOVED_TO_MARKER_TTL_SECS, 10);

        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn set_user_moved_to_voice(");
        assert!(
            body.contains(
                ".set_ex( format!(\"moved_to:\u{7b}user_id\u{7d}:\u{7b}new_channel_id\u{7d}\"), \
                 old_channel, MOVED_TO_MARKER_TTL_SECS, )"
            ),
            "`set_user_moved_to_voice` must expire the marker after \
             `MOVED_TO_MARKER_TTL_SECS`: {body}"
        );
    }

    /// B8 (5b-2.1 audit): the idle reads and the clear pass (user, server) in
    /// that order to builders pinned by value in afk_idle.rs, and the due read
    /// passes `now_ms` as its upper bound. The async wrappers need Redis to
    /// run, so their call sites are pinned on their text. Mutation: any
    /// argument pair swapped.
    #[test]
    fn the_idle_reads_and_clear_pass_user_then_server() {
        const FILE: &str = "core/database/src/voice/afk_idle.rs";
        let shipping = shipping_sources()
            .into_iter()
            .find(|(rel, _)| rel == FILE)
            .expect("afk_idle.rs is not in the workspace scan")
            .1;

        for (definition, call) in [
            (
                "pub async fn read_idle_state(",
                "idle_state_read_cmd(user_id, server_id)",
            ),
            (
                "pub async fn clear_afk_since(",
                "afk_since_clear_pipeline(user_id, server_id)",
            ),
            (
                "pub async fn get_afk_since(",
                "afk_since_key(user_id, server_id)",
            ),
            (
                "pub async fn due_idle_members(",
                "afk_idle_due_cmd(now_ms, limit)",
            ),
        ] {
            let body = flat_fn_body(&shipping, definition);
            assert!(
                body.contains(call),
                "`{definition}` must call `{call}`: {body}"
            );
        }
    }

    /// S-c: a room the SFU says does not exist is `NotConnected`, not a 500.
    /// The move lists through `list_participants_if_present` — the call that
    /// classifies a Twirp `not_found` as `None` — and binds the list with a
    /// `let ... else` whose `else` is the `NotConnected` return. That is the
    /// only listing `VoiceClient` has; this test keeps a plain
    /// `.list_participants(` call from ever coming back into the move,
    /// because a plain listing would turn a gone room into an error — a 500
    /// plus a Sentry event on every sweep tick.
    #[test]
    fn the_move_answers_a_gone_source_room_with_not_connected() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(
            !body.contains(".list_participants("),
            "the move lists through `list_participants(` again — a room the \
             SFU no longer has becomes a 500 and a Sentry event per sweep tick"
        );
        assert!(
            flat.contains(
                "let Some(participants) = voice_client \
                 .list_participants_if_present(&old_node, &from) .await? else"
            ),
            "the listing must bind `Some(participants)`, so a gone room \
             (`None`) takes the `else`"
        );

        let listing = first(&flat, ".list_participants_if_present(");
        let else_keyword = listing + first(&flat[listing..], ".await? else");
        let open = else_keyword + first(&flat[else_keyword..], "\u{7b}");
        let else_arm = braced_body(&flat, open);
        assert!(
            else_arm
                .trim()
                .ends_with("return Ok(VoiceMoveOutcome::NotConnected);"),
            "the `else` of the listing must answer `NotConnected`, and nothing \
             else: {else_arm}"
        );
    }

    /// P-2 (Wave 5a CRITICAL-1): the move event goes out strictly before the
    /// first removal, and no removal path that bypasses the SFU's listing or
    /// its NotFound classification is left in the move. The event is
    /// published on the owning session's topic (merge slice F2), so that is
    /// the publish this orders. The whole-user removals
    /// (`remove_user_from_voice_channel`, `remove_user_from_server_voice`,
    /// `tear_down_removed_connections`) are banned too: each lists the room
    /// again, and a `Nobody` move built on one of them would be a second,
    /// later eviction set.
    #[test]
    fn the_move_emits_before_it_evicts_and_only_through_the_listing() {
        let body = move_body_code();

        assert!(
            first(&body, ".private_session(") < first(&body, "remove_identity_if_present("),
            "the move event must be emitted BEFORE the first removal: a Leave \
             reaches the client ahead of a later event, and a client already \
             out of CONNECTED drops its own move"
        );

        // `remove_user_if_present(` (S-3 D-2) lists the room itself: the move
        // keeps its own pre-write listing and must evict from THAT, never
        // from a second, later one. `remove_user_if_present_sids(` (S-3
        // WA-R) is the same listing returning sids, and the needle above does
        // not match it, so it is banned by name. `remove_connection_if_present(`
        // (S-3 D-2) removes one connection with no listing at all, and derives
        // a leg the listing may not have reported: the move evicts exactly the
        // listed targets. (The mapping-resolved `remove_user(` that used to
        // head this list was deleted in the S-3 cleanup; the workspace pin
        // `the_deleted_sfu_methods_stay_gone` keeps it from coming back.)
        for banned in [
            "remove_identity(",
            "remove_user_if_present(",
            "remove_user_if_present_sids(",
            "remove_connection_if_present(",
            "remove_user_from_voice_channel(",
            "remove_user_from_server_voice(",
            "tear_down_removed_connections(",
        ] {
            assert!(
                !body.contains(banned),
                "the voice move calls `{banned}` — it must evict \
                 only the listed connections, through `remove_identity_if_present`"
            );
        }
    }

    /// T-gap: the move evicts through `eviction_targets` and
    /// `remove_identity_if_present`. Reverting it to a single mapped removal
    /// left every earlier test green.
    ///
    /// NEW-1 (Stage 5 re-audit): naming the two calls was not enough. Each of
    /// these one-token edits compiled and shipped green, and each is a move
    /// that reports `Moved` while connections of the target keep publishing
    /// into the source room:
    ///
    /// - evicting on `&new_node` — on a cross-node move the removal goes to
    ///   the wrong SFU, which has no such room and evicts nothing;
    /// - evicting from `destination.id()` rather than `&from` — the wrong
    ///   room, the one the target is being moved INTO;
    /// - feeding `eviction_targets` only the chosen connection
    ///   (`std::iter::once(moving.identity.clone())`) — every sibling stays.
    ///
    /// So the ARGUMENTS are pinned exactly, whitespace-flattened with comment
    /// lines dropped: the node and room the source was LISTED from are the
    /// node and room evicted from, and the eviction set is built from the
    /// WHOLE listing.
    #[test]
    fn the_move_evicts_every_listed_connection() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        // `old_node` is the SOURCE's node, bound once and never rebound.
        first(
            &flat,
            "let Some(old_node) = get_channel_node(&from).await? else",
        );
        assert_eq!(
            flat.matches("Some(old_node)").count(),
            1,
            "`old_node` must be bound exactly once, to the source's node"
        );
        for rebind in ["let old_node", "let mut old_node"] {
            assert!(
                !flat.contains(rebind),
                "`old_node` is rebound (`{rebind}`), so the node evicted on may \
                 no longer be the node the source was listed on"
            );
        }

        // The listing is taken from that node and the source room, and binds
        // `participants`, which nothing rebinds.
        assert_eq!(
            flat.matches(".list_participants_if_present(").count(),
            1,
            "the move must list the source room exactly once"
        );
        first(
            &flat,
            "let Some(participants) = voice_client \
             .list_participants_if_present(&old_node, &from) .await? else",
        );
        for rebind in ["let participants", "let mut participants"] {
            assert!(
                !flat.contains(rebind),
                "`participants` is rebound (`{rebind}`), so the eviction set \
                 may no longer be the listing"
            );
        }

        // The eviction set is built from the FULL listing, for the target.
        assert_eq!(
            flat.matches("eviction_targets(").count(),
            1,
            "the move must compute its eviction set exactly once"
        );
        first(
            &flat,
            "let evictions = eviction_targets( participants .iter() \
             .map(|participant| participant.identity.clone()), &target.id, );",
        );

        // And every one of them is removed from the node and room it was
        // listed in, inside the loop over that set.
        assert_eq!(
            flat.matches("remove_identity_if_present(").count(),
            1,
            "the move must evict through exactly one removal call"
        );
        let for_at = first(&flat, "for eviction in evictions ");
        let open = for_at + first(&flat[for_at..], "\u{7b}");
        let loop_body = braced_body(&flat, open);
        assert!(
            loop_body.contains(
                "voice_client .remove_identity_if_present(&old_node, &eviction.identity, &from) \
                 .await;"
            ),
            "each eviction must be removed from the SOURCE node and room it was \
             listed in (`&old_node`, `&from`), by its own identity: {loop_body}"
        );
    }

    /// B-1 + M-4, INVERTED by the merge slice (F1, F12): the move event's
    /// addressing fields come from ONE `move_addressing` call on the
    /// connection `select_move_connection` chose, but the TOKEN is minted
    /// from the delivery plan and nothing else. It used to be minted for
    /// `addressing.device_id` unconditionally, which is exactly the F1 hole:
    /// a device-qualified token handed to a session that is not the one the
    /// device is bound to lets its holder sit in the destination AS that
    /// device. Now:
    ///
    /// - the device is `qualified_move_device` of the CHOSEN connection, and
    ///   that same `device` feeds both the identity-row read
    ///   (`fetch_device_identity`) and the delivery (`move_event_delivery`),
    ///   so the binding checked is the binding of the device minted for;
    /// - the mint happens only inside `match plan.mint`, for `token_device`,
    ///   and `addressing.device_id` is banned from its arguments (controls
    ///   MINTDEV and TOKEN-ALWAYS);
    /// - the event names the chosen connection (`device_id`, `conn_nonce`)
    ///   only through `owner_addressing`, which keeps them only when the
    ///   connection is proven the recorded session's (F12's nonce rule).
    ///
    /// R3-2: the preference handed to `select_move_connection` is the
    /// mapping of the SOURCE room for the TARGET, bound once. Each of these
    /// compiles and reads the wrong mapping or none: the two arguments
    /// swapped (a key named after the user, a field named after the room),
    /// the mapping read for `destination.id()` instead of `&from`, and the
    /// read replaced with `None`.
    ///
    /// The event literal's `from` / `to` are pinned for the same reason:
    /// `to: from.clone()` compiles and names the room being left as the
    /// destination.
    #[test]
    fn the_move_event_addresses_the_connection_it_chose() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        first(
            &flat,
            "let mapped_identity = stored_voice_participant_identity(&from, &target.id).await?;",
        );
        assert_eq!(
            flat.matches("let mapped_identity").count(),
            1,
            "`mapped_identity` must be bound exactly once, to the source room's \
             mapping for the target"
        );
        assert!(
            !flat.contains("let mut mapped_identity"),
            "`mapped_identity` must not be mutable: the preference is the \
             mapping as read, nothing else"
        );

        // Whitespace removed and trailing commas folded, so the needles below
        // do not depend on how a long call happens to be wrapped.
        let squeezed: String = flat.split_whitespace().collect::<String>().replace(",)", ")");

        // F12 / M2B-7 / RRB-1: the owner's own listed seat is preferred,
        // ahead of the mapping, decided from the seat kind recorded with the
        // owner in the SOURCE record (one read), which also decides the only
        // token the owner may get.
        let recorded = first(
            &squeezed,
            "letowner_seat=owner_recorded_seat(owner,\
             get_voice_participant_session_seat(&from,&target.id).await?);",
        );
        let seat = first(
            &squeezed,
            "letowner_identity=owner_listed_seat(&participants,&target.id,&owner_seat);",
        );
        assert!(recorded < seat, "{flat}");
        assert_eq!(
            flat.matches("get_voice_participant_session_seat(").count(),
            1,
            "{flat}"
        );
        assert_eq!(flat.matches("owner_recorded_seat(").count(), 1, "{flat}");
        assert_eq!(flat.matches("let owner_seat").count(), 1, "{flat}");
        assert!(
            squeezed.contains(
                "letSome(moving)=select_move_connection(&participants,&target.id,\
                 owner_identity.as_deref(),mapped_identity.as_deref())else"
            ),
            "`moving` must be the connection chosen from the SFU's list: {flat}"
        );
        assert_eq!(
            flat.matches("move_addressing(").count(),
            1,
            "the addressing must be computed exactly once"
        );
        let addressing = first(
            &flat,
            "let addressing = move_addressing(moving, &target.id);",
        );
        assert!(
            addressing < first(&flat, ".create_token("),
            "the addressing must exist before the token is minted"
        );

        // The device the delivery is decided for is the CHOSEN connection's,
        // qualified only under media E2EE, and the SAME `device` feeds the
        // identity-row read and the delivery.
        assert_eq!(
            squeezed
                .matches("letdevice=qualified_move_device(&moving.identity,&target.id,")
                .count(),
            1,
            "the device must be `qualified_move_device` of the chosen connection: {flat}"
        );
        let row = first(
            &squeezed,
            "letidentity_row=matchdevice\u{7b}Some(device_id)=>\
             fetch_device_identity(db,&target.id,device_id).await?,None=>None,\u{7d};",
        );
        // Merge slice SEC4-1: a bare token only for the chosen connection's
        // own bare seat, so whether the CHOSEN connection is the bare seat
        // is decided from `moving` itself, once, and handed to the delivery.
        assert_eq!(
            squeezed
                .matches("letbare_seat_chosen=moving.identity==target.id;")
                .count(),
            1,
            "whether the bare seat was chosen must be `moving`'s own identity: {flat}"
        );
        assert_eq!(flat.matches("bare_seat_chosen").count(), 2, "{flat}");
        let delivery = first(
            &squeezed,
            "letdelivery=move_event_delivery(owner,&owner_seat,device,bare_seat_chosen,",
        );
        let plan = first(&squeezed, "letplan=move_token_plan(&delivery);");
        assert!(
            recorded < delivery && row < delivery && delivery < plan,
            "{flat}"
        );
        assert!(
            squeezed[delivery..plan].ends_with(".map(|row|row.last_session_id.as_str()));"),
            "the delivery is decided for the owner's recorded seat kind and the chosen \
             device's binding, nothing else: {flat}"
        );
        // The carry-over carries the same recorded seat kind the delivery was
        // planned on, for the planned session.
        assert!(
            squeezed.contains(
                "ifletSome(session_id)=plan.session\u{7b}if!carry_voice_participant_session(\
                 &from,destination.id(),&target.id,session_id,&owner_seat).await?"
            ),
            "the carry-over must carry the planned session with the recorded seat: {flat}"
        );
        // Two reads of the binding, both of the plan's device: the one the
        // delivery is planned on (pinned above), and the re-read right before
        // the owner re-check, for a device token only (media-e2ee S6M-3,
        // `the_move_re_reads_the_device_binding_right_before_the_owner_re_check`).
        assert_eq!(flat.matches("fetch_device_identity(").count(), 2, "{flat}");
        assert_eq!(
            squeezed
                .matches("fetch_device_identity(db,&target.id,token_device)")
                .count(),
            1,
            "the second read is the re-read of the minted device: {flat}"
        );
        assert_eq!(flat.matches("move_event_delivery(").count(), 1, "{flat}");

        // The token is minted ONLY inside `match plan.mint`, for
        // `token_device`, and never for `addressing.device_id`.
        assert_eq!(flat.matches(".create_token(").count(), 1, "{flat}");
        let mint_match = first(&squeezed, "lettoken=matchplan.mint\u{7b}None=>None,");
        let mint = first(&squeezed, ".create_token(");
        let arm = first(&squeezed, "Some(token_device)=>Some(");
        assert!(
            mint_match < arm && arm < mint,
            "the mint must sit in the `Some(token_device)` arm of `match plan.mint`: {flat}"
        );
        let mint_args = &squeezed[mint..mint + first(&squeezed[mint..], ".await?")];
        assert_eq!(
            mint_args, ".create_token(&new_node,db,target,permissions,destination,token_device)",
            "the token must be minted for the plan's `token_device` and nothing else"
        );
        assert!(
            !mint_args.contains("addressing"),
            "the token must never be minted for the addressing: {mint_args}"
        );

        // The event literal's addressing fields come from the owner-proven
        // addressing (F12), and nothing else feeds them.
        first(
            &squeezed,
            "letevent_addressing=owner_addressing(&plan,&addressing);",
        );
        let literal_at = first(&flat, "EventV1::UserMoveVoiceChannel");
        let open = literal_at + first(&flat[literal_at..], "\u{7b}");
        let literal = braced_body(&flat, open);
        let fields: Vec<&str> = literal.split(',').map(str::trim).collect();
        assert!(
            fields.contains(&"device_id: event_addressing.device_id"),
            "the event's `device_id` must be the owner-proven addressing's: {literal}"
        );
        assert!(
            fields.contains(&"conn_nonce: event_addressing.conn_nonce"),
            "the event's `conn_nonce` must be the owner-proven addressing's: {literal}"
        );
        assert!(
            fields.contains(&"url: Some(url)") && fields.contains(&"token"),
            "the event carries the node's public URL and the planned token: {literal}"
        );
        assert!(
            fields.contains(&"from: from.clone()"),
            "the event's `from` must be the source room: {literal}"
        );
        assert!(
            fields.contains(&"to: destination.id().to_string()"),
            "the event's `to` must be the destination room: {literal}"
        );
        assert!(
            !literal.contains("mapped_identity") && !literal.contains("None"),
            "the event literal must not address from the mapping, nor hard-code \
             an absent field: {literal}"
        );
    }

    /// Same class as R3-2: the raw mapping read is the ingress write's
    /// mirror, `voice_identity:{channel}` keyed and the BARE user id as the
    /// field (`set_voice_participant_identity`'s `hset`). With key and field
    /// swapped it compiles and reads a key the ingress never writes, so the
    /// move loses its preference.
    #[test]
    fn the_raw_identity_read_mirrors_the_ingress_write() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "async fn stored_voice_participant_identity(");

        assert!(
            body.contains(".hget(format!(\"voice_identity:\u{7b}channel_id\u{7d}\"), user_id)"),
            "`stored_voice_participant_identity` must read field `user_id` of \
             `voice_identity:{{channel_id}}`, as the ingress writes it: {body}"
        );
    }

    /// A0-3 (5b-2.0 audit): the write side of the same mapping. Renaming the
    /// `hset` key compiles and ships green, and then every reader above
    /// resolves nothing: the move loses its preference and every kick or
    /// permission update falls back to the bare user id.
    #[test]
    fn the_ingress_identity_write_is_the_key_the_readers_use() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn set_voice_participant_identity(");

        assert!(
            body.contains(
                ".hset(format!(\"voice_identity:\u{7b}channel_id\u{7d}\"), user_id, identity)"
            ),
            "`set_voice_participant_identity` must write field `user_id` of \
             `voice_identity:{{channel_id}}`: {body}"
        );
    }

    /// I-2 (Wave 5b-2): every join deletes the AFK idle claim, inside
    /// `create_voice_state`'s pipeline, through the one key builder. Without
    /// it a claim from the previous call (live for up to its TTL) carries
    /// over into the next one, and the sweep's `since >= joined_at` check is
    /// left as the only guard against moving an active member.
    #[test]
    fn a_join_deletes_the_idle_claim() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn create_voice_state(");

        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`create_voice_state` lost `{needle}`: {body}"))
        };
        let pipeline = at("Pipeline::new()");
        let run = at(".query_async");
        let delete = at(".del(afk_idle::afk_since_key( user_id, \
             channel.server_id.as_ref().unwrap_or(&channel.id), ))");
        assert!(
            pipeline < delete && delete < run,
            "the claim DEL must be part of the join pipeline: {body}"
        );
    }

    /// AFK S-3 RA2-5: a join writes its two roster memberships LAST, right
    /// before the pipeline runs, after every key `get_voice_state` reads. The
    /// pipeline is not a transaction, so the roster repair in
    /// `get_channel_voice_state` can read between its commands, and it tears
    /// down (whole-user) any `vc_members` entry whose state it cannot read.
    /// A membership written first exposes the half-written join to it. The
    /// interleaving cannot be forced from a test, so the order is pinned on
    /// the text. Mutation: the two `.sadd(` moved back to the head.
    #[test]
    fn a_join_writes_the_roster_memberships_last() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn create_voice_state(");

        const TAIL: &str = ".sadd(format!(\"vc_members:\u{7b}\u{7d}\", &channel.id), user_id) \
             .sadd(format!(\"vc:\u{7b}user_id\u{7d}\"), channel) .query_async";
        assert_eq!(body.matches(TAIL).count(), 1, "{body}");
        assert_eq!(body.matches(".sadd(").count(), 2, "{body}");

        let memberships = first(&body, TAIL);
        for write in [".set(", ".del("] {
            let last = body
                .rfind(write)
                .unwrap_or_else(|| panic!("no `{write}`: {body}"));
            assert!(
                last < memberships,
                "a `{write}` follows the roster memberships: {body}"
            );
        }
        assert!(
            body.matches(".set(").count() >= 10,
            "the pointer and the nine flags: {body}"
        );
    }

    /// The one afk_idle.rs function that writes a claim, pinned on its
    /// shipping text: the since arithmetic is `afk_since_ms` with the join
    /// clamp, the write is decided by `afk_since_write` and issued by
    /// `afk_since_write_cmd`, and the index entry is re-added with
    /// `afk_idle_add_cmd` (ZADD NX). The builders' exact commands (`SET … NX
    /// EX 180`, `ZADD afk_idle NX …`) are pinned by value in afk_idle.rs.
    #[test]
    fn a_claim_is_written_through_the_pinned_builders() {
        const FILE: &str = "core/database/src/voice/afk_idle.rs";
        let shipping = shipping_sources()
            .into_iter()
            .find(|(rel, _)| rel == FILE)
            .expect("afk_idle.rs is not in the workspace scan")
            .1;
        let body = flat_fn_body(&shipping, "pub async fn set_afk_since(");

        for needle in [
            "idle_state_keys(user_id, server_id)",
            ".mget(&[key.as_str(), joined_at_key.as_str()])",
            // Stage 6 F-A2: one `now` for the join refusal and the stamp.
            "let now = now_ms();",
            "afk_since_ms(now, idle_for, joined_at_ms)",
            "afk_since_write(existing_claim.as_ref(), channel_id)",
            "afk_since_write_cmd(write, &key, &fresh)",
            "afk_idle_add_cmd( &afk_idle_member(user_id, server_id), since_ms + INDEX_FIRST_LOOK_MS, )",
        ] {
            assert!(body.contains(needle), "`set_afk_since` lost `{needle}`: {body}");
        }

        let write_cmd = flat_fn_body(&shipping, "fn afk_since_write_cmd(");
        for needle in [
            "SetExpiry::EX(AFK_SINCE_TTL_SECS as usize)",
            "ExistenceCheck::NX",
            "ExistenceCheck::XX",
        ] {
            assert!(
                write_cmd.contains(needle),
                "`afk_since_write_cmd` lost `{needle}`: {write_cmd}"
            );
        }
        let add_cmd = flat_fn_body(&shipping, "fn afk_idle_add_cmd(");
        assert!(
            add_cmd.contains("cmd(\"ZADD\")") && add_cmd.contains(".arg(\"NX\")"),
            "`afk_idle_add_cmd` must be a raw ZADD NX: {add_cmd}"
        );
    }

    /// M4-b (Wave 5b-2): the `moved_from` marker is gone end to end. It
    /// suppressed the source's Leave, and when no destination join followed
    /// (a dropped event, a refused connect) the old roster kept a ghost on
    /// every other client. Reintroducing it anywhere in the workspace fails
    /// here; the ingress half is pinned in voice-ingress `api.rs`.
    #[test]
    fn the_moved_from_marker_is_gone() {
        for (rel, shipping) in shipping_sources() {
            for needle in ["moved_from:", "_moved_from_voice("] {
                assert!(
                    !shipping.contains(needle),
                    "{rel} contains `{needle}` — the source's Leave must never \
                     be suppressed again"
                );
            }
        }
    }

    /// I-16: the source == destination guard answers `AlreadyPresent` before
    /// `admit_voice_move` runs. Pinned on `move_body_code` (the braced body,
    /// comment lines dropped). Deleting the guard re-kicks every AFK
    /// occupant on every sweep tick; `!=` refuses every real move; moving it
    /// below admission makes an occupant of a full, capped AFK channel
    /// answer `CannotJoinCall` on every tick.
    #[test]
    fn the_move_answers_already_present_before_admission() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        let guard = first(
            &flat,
            "if from == destination.id() \u{7b} \
             return Ok(VoiceMoveOutcome::AlreadyPresent); \u{7d}",
        );
        assert!(
            guard < first(&flat, "admit_voice_move("),
            "the source == destination guard must precede `admit_voice_move(`"
        );
    }

    /// `move_addressing` by value: the device suffix and the nonce both come
    /// from the participant it is handed, and only from it.
    #[test]
    fn move_addressing_reads_the_moving_connection() {
        use super::{move_addressing, MoveAddressing};

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";

        assert_eq!(
            move_addressing(&listed(user, 0, Some("N-BARE")), user),
            MoveAddressing {
                device_id: None,
                conn_nonce: Some("N-BARE".to_string()),
            },
            "a bare seat has no device suffix, and its nonce is what names it"
        );
        assert_eq!(
            move_addressing(&listed(&format!("{user}:D1"), 0, Some("N-D1")), user),
            MoveAddressing {
                device_id: Some("D1".to_string()),
                conn_nonce: Some("N-D1".to_string()),
            }
        );
        assert_eq!(
            move_addressing(&listed(&format!("{user}:D2"), 0, Some("")), user),
            MoveAddressing {
                device_id: Some("D2".to_string()),
                conn_nonce: None,
            },
            "an empty nonce addresses nothing"
        );
        assert_eq!(
            move_addressing(&listed(&format!("{user}:D3"), 0, None), user),
            MoveAddressing {
                device_id: Some("D3".to_string()),
                conn_nonce: None,
            }
        );
    }

    /// B-3: what the evictions amount to. `Ok(true)` and `Ok(false)` succeed
    /// for either kind; an `Err` on a LISTED connection fails the move (the
    /// first such error is the one returned); an `Err` on a derived leg does
    /// not.
    #[test]
    fn eviction_result_fails_only_on_a_listed_connection() {
        use super::{eviction_result, VoiceEviction};

        fn listed_one(identity: &str) -> VoiceEviction {
            VoiceEviction {
                identity: identity.to_string(),
                reported: true,
            }
        }
        fn derived_leg(identity: &str) -> VoiceEviction {
            VoiceEviction {
                identity: identity.to_string(),
                reported: false,
            }
        }

        assert_eq!(
            eviction_result::<&str>([
                (derived_leg("u::screen"), Ok(false)),
                (listed_one("u"), Ok(false)),
                (listed_one("u:D1"), Ok(true)),
            ]),
            Ok(()),
            "removed and already-gone are both success"
        );
        assert_eq!(
            eviction_result([
                (derived_leg("u:D1:screen"), Err("leg 500")),
                (listed_one("u:D1"), Ok(true)),
            ]),
            Ok(()),
            "a derived leg's failure is discarded"
        );
        assert_eq!(
            eviction_result([
                (derived_leg("u::screen"), Ok(false)),
                (listed_one("u"), Err("primary 500")),
                (listed_one("u:D1"), Ok(true)),
            ]),
            Err("primary 500"),
            "a listed connection that could not be removed fails the move, \
             even when a later removal succeeds"
        );
        assert_eq!(
            eviction_result([
                (derived_leg("u::screen"), Err("leg 500")),
                (listed_one("u"), Err("first listed 500")),
                (listed_one("u:D1"), Err("second listed 500")),
            ]),
            Err("first listed 500"),
            "the FIRST listed failure is returned, never a discarded leg's"
        );
        assert_eq!(eviction_result::<&str>([]), Ok(()));
    }

    /// B-3, the loop half: every removal is issued before the outcome is
    /// decided. The eviction loop has no early exit (no `?` operator, no
    /// `return`, no `break`), and `eviction_result` runs after it, on every
    /// outcome. The `?` needles are the operator's shapes, not a bare `?`,
    /// because the loop's log line formats with `:?`.
    #[test]
    fn the_move_attempts_every_eviction_before_deciding() {
        let body = move_body_code();

        let loop_at = first(&body, "for eviction in evictions");
        let open = loop_at + first(&body[loop_at..], "\u{7b}");
        let loop_body = braced_body(&body, open);
        for exit in [".await?", ")?", "return", "break"] {
            assert!(
                !loop_body.contains(exit),
                "the eviction loop contains `{exit}` — one failed removal must \
                 not leave the remaining connections in the room: {loop_body}"
            );
        }
        assert!(
            loop_body.contains("outcomes.push((eviction, outcome));"),
            "every outcome must be recorded: {loop_body}"
        );

        let decided = first(&body, "eviction_result(outcomes)?;");
        assert!(
            decided > open + loop_body.len(),
            "`eviction_result` must run after the loop, on every outcome"
        );
    }

    // ---- the merge slice's delivery pins (AFK x voice-move, lane P1) ----

    /// The brace depth at byte `at` of `text`: 0 is a top-level statement of
    /// the scanned body. A brace in a string or char literal or in a comment
    /// does not count (merge slice S6F3A-2): the depth is read off
    /// [`blanked`] text.
    fn depth_at(text: &str, at: usize) -> i64 {
        blanked("the scanned body", text, true)[..at]
            .chars()
            .fold(0, |depth, ch| match ch {
                '\u{7b}' => depth + 1,
                '\u{7d}' => depth - 1,
                _ => depth,
            })
    }

    /// The `(arm, index just past its closing brace)` of the block that opens
    /// at the first `\u{7b}` at or after `from` in `flat`.
    fn block_after(flat: &str, from: usize) -> (&str, usize) {
        let open = from + first(&flat[from..], "\u{7b}");
        let arm = braced_body(flat, open);
        (arm, open + arm.len() + 2)
    }

    /// Media-e2ee final audit F1, merge slice F2 (voice-move red #5, ported
    /// onto the merged move). The move event is published ONCE, on the topic
    /// of the session the plan names, and only when it names one; the
    /// `Nobody` arm publishes, prepares and mints nothing. Control D swapped
    /// the publish for `.private(target.id.clone())` (every session of the
    /// user) and every other test stayed green: the AFK pins used to REQUIRE
    /// that form. The order is voice-move's, re-anchored on AFK's
    /// emit-before-evict: the owner re-check, then the event, then its
    /// publish, then the evictions.
    #[test]
    fn the_move_event_is_published_only_to_the_planned_session() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        for user_wide in [".private(", ".p(", ".p_user(", ".global("] {
            assert_eq!(
                flat.matches(user_wide).count(),
                0,
                "the voice move must not publish with `{user_wide}` (every session of the \
                 user, or wider): {flat}"
            );
        }
        assert_eq!(
            flat.matches(".private_session(").count(),
            1,
            "the voice move publishes on exactly one session topic: {flat}"
        );
        assert_eq!(flat.matches("EventV1::").count(), 1, "one event: {flat}");
        assert_eq!(
            flat.matches("let plan = move_token_plan(&delivery);").count(),
            1,
            "the plan comes from the delivery, once: {flat}"
        );
        assert_eq!(
            flat.matches("match plan.session \u{7b}").count(),
            1,
            "the move branches on the plan's session exactly once: {flat}"
        );

        let matched = first(&flat, "match plan.session \u{7b}");
        let some_at = matched + first(&flat[matched..], "Some(session_id) => \u{7b}");
        let (some_arm, some_end) = block_after(&flat, some_at);
        let none_at = some_end + first(&flat[some_end..], "None => \u{7b}");
        let (none_arm, _) = block_after(&flat, none_at);

        let event = first(some_arm, "EventV1::UserMoveVoiceChannel");
        let publish = first(some_arm, ".private_session(session_id.to_string())");
        assert!(event < publish, "built, then published: {some_arm}");

        for moved in [
            "EventV1::",
            "create_room(",
            "create_token(",
            "set_user_moved_",
            "set_channel_node(",
            "set_move_admission(",
        ] {
            assert!(
                !none_arm.contains(moved),
                "no owner: `{moved}` must not happen: {none_arm}"
            );
        }

        let recheck = first(&flat, "voice_participant_record_is(");
        let event = first(&flat, "EventV1::UserMoveVoiceChannel");
        let publish = first(&flat, ".private_session(");
        let evict = first(&flat, "for eviction in evictions");
        assert!(
            recheck < event && event < publish && publish < evict,
            "the owner re-check, then the event, then its publish, then the evictions: {flat}"
        );
    }

    /// Merge slice F2, the workspace half, STATEMENT-scoped: no shipping
    /// statement that builds a `UserMoveVoiceChannel` publishes it with a
    /// user-wide (or wider) publisher, and every such statement publishes it
    /// to one session in the same statement, so a move event cannot be bound
    /// to a variable and published elsewhere. File-scoped would be wrong:
    /// `users/model.rs` publishes an unrelated event with `.private(`.
    #[test]
    fn no_statement_publishes_the_move_event_user_wide() {
        const EVENTS: &str = "core/database/src/events/client.rs";

        /// The statement starting at `at`: up to its `;` at depth zero, or to
        /// the brace or parenthesis that closes the expression it sits in.
        fn statement_from(shipping: &str, at: usize) -> &str {
            let mut depth = 0i64;
            for (i, ch) in shipping[at..].char_indices() {
                match ch {
                    '\u{7b}' | '(' | '[' => depth += 1,
                    '\u{7d}' | ')' | ']' => {
                        depth -= 1;
                        if depth < 0 {
                            return &shipping[at..at + i];
                        }
                    }
                    ';' if depth == 0 => return &shipping[at..at + i + 1],
                    _ => {}
                }
            }
            &shipping[at..]
        }

        let mut constructions = 0;
        for (rel, shipping) in shipping_sources() {
            for (at, _) in shipping.match_indices("UserMoveVoiceChannel") {
                let line_start = shipping[..at].rfind('\n').map_or(0, |nl| nl + 1);
                let line = shipping[line_start..].trim_start();
                if line.starts_with("//") {
                    continue;
                }
                // The variant's own declaration in the event enum.
                if rel == EVENTS && line.starts_with("UserMoveVoiceChannel \u{7b}") {
                    continue;
                }

                constructions += 1;
                let statement = statement_from(&shipping, at);
                for user_wide in [".private(", ".p(", ".p_user(", ".global("] {
                    assert!(
                        !statement.contains(user_wide),
                        "{rel}: a move event is published with `{user_wide}`: {statement}"
                    );
                }
                assert!(
                    statement.contains(".private_session("),
                    "{rel}: a move event must be built and published to ONE session in one \
                     statement: {statement}"
                );
            }
        }
        assert!(
            constructions >= 1,
            "the scan found no move event at all, so it proves nothing"
        );
    }

    /// Merge slice F4: the owner re-check (`voice_participant_record_is`,
    /// the whole record since merge slice SEC4-2) runs AFTER the mint and
    /// BEFORE the marker, exactly once, as a top-level statement shared by
    /// the owner and the `Nobody` arm, and the session-only compare
    /// (`voice_participant_session_is`) is not used in the move at all
    /// (control RECHECK-SESSION). Before the release (control RECHECK-EARLY)
    /// it leaves the release, the mint's Mongo reads and the room creation
    /// as a window in which a `join_call` kick goes unseen. A Redis read, so
    /// the WC-1 "no SFU call between the mint and the emit" pin still holds.
    #[test]
    fn the_move_re_checks_the_owner_after_the_mint_and_before_the_marker() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        assert_eq!(
            flat.matches("voice_participant_record_is(").count(),
            1,
            "the move must re-check its owner exactly once: {flat}"
        );
        assert_eq!(
            flat.matches("voice_participant_session_is(").count(),
            0,
            "the move's re-check compares the whole record, never the session alone: {flat}"
        );
        let mint = first(&flat, ".create_token(");
        let recheck = first(&flat, "voice_participant_record_is(");
        let marker = first(&flat, "set_user_moved_to_voice(");
        assert!(
            first(&flat, "release_remote_control_for_user(") < recheck,
            "the re-check must follow the remote-control release: {flat}"
        );
        assert!(
            mint < recheck && recheck < marker,
            "`.create_token(` < `voice_participant_record_is(` < \
             `set_user_moved_to_voice(`: {flat}"
        );
        assert_eq!(
            depth_at(&flat, recheck),
            0,
            "the re-check is a top-level statement, shared by the owner and the Nobody arm: \
             {flat}"
        );
    }

    /// Voice-move red #4, ported: the re-check compares the SOURCE record
    /// with the planned owner (`plan.session`, `None` for no owner) and the
    /// seat kind the carry-over compared (`owner_seat`, merge slice SEC4-2),
    /// and a mismatch refuses `NotConnected` with nothing announced. Right before
    /// the event, not the removal: AFK announces before it evicts. The
    /// record is a plain read, not a compare-and-swap (m1_sec correction 1),
    /// so this re-check is the thing the security rests on (controls
    /// RECHECK, CAS).
    #[test]
    fn a_move_re_checks_the_source_owner_right_before_the_event() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        const RECHECK: &str =
            "if !voice_participant_record_is(&from, &target.id, plan.session, &owner_seat)\
             .await? \u{7b}";
        assert_eq!(flat.matches(RECHECK).count(), 1, "{flat}");
        let at = first(&flat, RECHECK);
        let (refusal, _) = block_after(&flat, at);
        assert!(
            refusal
                .trim()
                .ends_with("return Ok(VoiceMoveOutcome::NotConnected);"),
            "a changed owner must refuse the move: {refusal}"
        );
        assert!(
            !refusal.contains("voice_client.") && !refusal.contains(".private"),
            "the refusal announces nothing and touches no SFU: {refusal}"
        );
        assert!(
            at < first(&flat, "match plan.session \u{7b}")
                && at < first(&flat, "EventV1::UserMoveVoiceChannel"),
            "the re-check precedes the event: {flat}"
        );
    }

    /// Merge slice F7: ONE remote-control release, shared by the owner and
    /// the `Nobody` arm: a top-level statement after the destination is
    /// prepared and before the mint. A move that disconnects (`Nobody`) takes
    /// the participant out of the source like any other and must end its
    /// grant just the same.
    #[test]
    fn the_move_releases_remote_control_once_for_either_owner() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        assert_eq!(
            flat.matches("release_remote_control_for_user(").count(),
            1,
            "{flat}"
        );
        let release = first(&flat, "release_remote_control_for_user(");
        assert_eq!(
            depth_at(&flat, release),
            0,
            "the release must be a top-level statement, not inside an owner branch: {flat}"
        );
        assert!(
            first(&flat, "if plan.session.is_some() \u{7b}") < release
                && release < first(&flat, "match plan.mint \u{7b}"),
            "prepared destination < release < mint: {flat}"
        );
    }

    /// Merge slice: the destination is prepared (node pin, room) only for a
    /// move somebody will be told about, after the carry and before the
    /// release; the `Nobody` disconnect pins no node and opens no room.
    #[test]
    fn the_destination_is_prepared_only_for_a_move_somebody_is_told_about() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        for write in ["set_channel_node(", "create_room("] {
            assert_eq!(flat.matches(write).count(), 1, "{write}: {flat}");
        }
        let prepare = first(&flat, "if plan.session.is_some() \u{7b}");
        let (prepared, _) = block_after(&flat, prepare);
        assert!(
            prepared.contains("set_channel_node(destination.id(), &new_node).await?;")
                && prepared.contains("voice_client.create_room(&new_node, destination).await?;"),
            "the node pin and the room belong to the owner-only preparation: {prepared}"
        );
        assert!(
            first(&flat, "carry_voice_participant_session(") < prepare
                && prepare < first(&flat, "release_remote_control_for_user("),
            "carry < preparation < release: {flat}"
        );
    }

    /// Merge slice R8 / B6: NO teardown touches the session record. A leave
    /// that dropped it would lose it across livekit's full reconnect (which
    /// never calls `join_call`), and the next move would reach nobody; the
    /// connection teardowns reach the whole-user one on their `Last` path,
    /// which would wipe a newer join's record. Control LEAVE (a
    /// `voice_session` HDEL in the teardown script) fails here.
    #[test]
    fn no_voice_state_teardown_touches_the_session_record() {
        assert!(
            !super::DELETE_VOICE_STATE_LUA.contains("voice_session"),
            "the teardown script touches the session record"
        );
        let shipping = this_file_shipping();
        for teardown in [
            "fn voice_state_teardown_input(",
            "fn voice_connection_teardown_input(",
            "fn voice_connections_teardown_input(",
            "pub async fn delete_voice_state(",
            "async fn delete_voice_state_unconditionally(",
            "pub async fn delete_voice_connection(",
            "async fn delete_voice_connection_unconditionally(",
            "pub async fn delete_voice_connections(",
            "async fn delete_voice_connections_unconditionally(",
        ] {
            let body = flat_fn_body(&shipping, teardown);
            assert!(
                !body.contains("voice_session"),
                "`{teardown}` touches the session record: {body}"
            );
        }
    }

    /// Merge slice SEC2-1: the carry-over is ONE script invocation, the
    /// compare on the source and the write to the destination together, so
    /// a stalled carry can no longer land after a `join_call` kicked the
    /// planned session and wrote its own record into the destination. The
    /// function reads and writes nothing outside the script; the script
    /// compares `KEYS[1]` (the source) and writes only `KEYS[2]` (the
    /// destination); and its hash is pinned, because the deploy's EVAL /
    /// KeyDB ACL probe has to load exactly this script. Control SPLIT (the
    /// pre-fix read-then-write body) and control CAS-LUA (the compare made
    /// always true) fail here; CAS-LUA also fails the carry's behavioral
    /// test.
    #[test]
    fn the_session_carry_is_one_atomic_script() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn carry_voice_participant_session(");
        assert_eq!(
            body.matches(".invoke_async::<_, i64>(").count(),
            1,
            "the carry is one script invocation: {body}"
        );
        let squeezed: String = body.split_whitespace().collect();
        // Merge slice RRB-1: the script compares and writes the WHOLE record,
        // the session with its seat kind, so the destination records the
        // seat the move planned for (control CARRY-NOSEAT).
        assert!(
            squeezed.contains(
                "letrecord=voice_session_record(session_id,seat);\
                 letmutinvocation=CARRY_VOICE_PARTICIPANT_SESSION.prepare_invoke();invocation\
                 .key(voice_session_key(source_id))\
                 .key(voice_session_key(destination_id))\
                 .arg(user_id)\
                 .arg(record.as_str());"
            ),
            "KEYS[1] is the source, KEYS[2] the destination, then the user and the \
             whole record (the session and its seat kind): {body}"
        );
        for banned in [
            "voice_participant_session_is(",
            "voice_participant_record_is(",
            "get_voice_participant_session(",
            "set_voice_participant_session(",
            ".hget(",
            ".hset(",
            ".hdel(",
            ".del(",
            "Pipeline",
        ] {
            assert!(
                !body.contains(banned),
                "the carry reads or writes outside its one script (`{banned}`): {body}"
            );
        }

        let lua = super::CARRY_VOICE_PARTICIPANT_SESSION_LUA
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            lua,
            "if ARGV[2] ~= '' and redis.call('HGET', KEYS[1], ARGV[1]) == ARGV[2] then \
             redis.call('HSET', KEYS[2], ARGV[1], ARGV[2]) return 1 end return 0",
            "compare the source, write the destination, nothing else"
        );
        assert_eq!(
            super::CARRY_VOICE_PARTICIPANT_SESSION.get_hash(),
            "0d190f793c66fde6dd13a87624d933ee01db1e2b",
            "the carry script changed: update the deploy's EVAL / ACL probe with the new hash"
        );
    }

    /// Every `fn` item of `shipping` that has a body, as (name, byte of its
    /// opening brace, byte just past its closing brace). A header is `fn `
    /// (not the tail of a longer word) followed by an identifier and `(` or
    /// `<`, whatever precedes it on its line (`pub(in ...)`, `pub(crate)`,
    /// `const`, `async`, `unsafe`, `extern "C"`, an attribute); its body is
    /// the first brace outside the signature's parentheses and brackets, and
    /// a `;` there first is a bodyless declaration. Read off [`blanked`] text
    /// (merge slice S6R-4), so a `fn ` or a brace in a comment or a literal is
    /// none, and a header line with a `//` in a string before its `fn` (an
    /// attribute's URL) is still a header: a line used to be skipped whole
    /// for any `//` before the `fn`.
    fn fn_bodies(shipping: &str) -> Vec<(String, usize, usize)> {
        let shipping = &blanked("fn_bodies", shipping, true);
        let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
        let mut bodies = Vec::new();
        for (at, _) in shipping.match_indices("fn ") {
            if shipping[..at].chars().next_back().is_some_and(is_ident) {
                continue;
            }
            let rest = &shipping[at + 3..];
            let name: String = rest.chars().take_while(|ch| is_ident(*ch)).collect();
            let opens = rest[name.len()..].trim_start().chars().next();
            if name.is_empty() || !matches!(opens, Some('(' | '<')) {
                continue;
            }
            let mut depth = 0i64;
            let mut open = None;
            for (i, ch) in rest.char_indices() {
                match ch {
                    '(' | '[' => depth += 1,
                    ')' | ']' => depth -= 1,
                    ';' if depth == 0 => break,
                    '\u{7b}' if depth == 0 => {
                        open = Some(at + 3 + i);
                        break;
                    }
                    _ => {}
                }
            }
            if let Some(open) = open {
                let close = open + braced_body(shipping, open).len() + 2;
                bodies.push((name, open, close));
            }
        }
        bodies
    }

    /// The name of the innermost `fn` whose braced body contains byte `at`
    /// of `shipping`, by BRACE SPAN (merge slice S6B-2 / RRB-3). It used to
    /// be the nearest header line above `at` that it could read, and it read
    /// only `pub`, `pub(crate)`, `pub(super)` and `async` before `fn `, so a
    /// builder whose header it could not read (`pub(in ...)`, `const`,
    /// `unsafe`, `extern`, an attribute on the same line) was attributed to
    /// the helper above it (probes RRB3-GAP-A, RRB3-GAP-B). FAILS CLOSED: a
    /// site inside no fn (a `const` or `static` initializer) or anywhere in
    /// a `macro_rules!` body panics, naming the byte. Both are read off
    /// [`blanked`] text, as [`fn_bodies`] is.
    fn enclosing_fn(shipping: &str, at: usize) -> String {
        let code = &blanked("enclosing_fn", shipping, true);
        for (start, _) in code.match_indices("macro_rules!") {
            let Some(offset) = code[start..].find(|ch: char| matches!(ch, '(' | '[' | '\u{7b}'))
            else {
                continue;
            };
            let open = start + offset;
            let mut depth = 0i64;
            let mut close = code.len();
            for (i, ch) in code[open..].char_indices() {
                match ch {
                    '(' | '[' | '\u{7b}' => depth += 1,
                    ')' | ']' | '\u{7d}' => {
                        depth -= 1;
                        if depth == 0 {
                            close = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            assert!(
                !(start..close).contains(&at),
                "a site at byte {at} sits inside a `macro_rules!` body: no fn can be named for it"
            );
        }

        fn_bodies(shipping)
            .into_iter()
            .filter(|(_, open, close)| *open < at && at < *close)
            .max_by_key(|(_, open, _)| *open)
            .map(|(name, _, _)| name)
            .unwrap_or_else(|| {
                panic!("a site at byte {at} is inside no fn (a `const` or `static` initializer?)")
            })
    }

    /// `enclosing_fn` by brace span, on a synthetic source: every header
    /// form the old textual read missed names its own fn (probes RRB3-GAP-A,
    /// RRB3-GAP-B), a nested fn wins over its parent, a commented-out header
    /// is no fn, and a site in a `static` initializer or in a `macro_rules!`
    /// body fails closed. Merge slice S6R-4: a header line with a `//` in a
    /// string before its `fn` still names its fn, a `fn ` or a brace inside a
    /// literal or a trailing comment is none, and a `macro_rules!` named in
    /// a comment hides nothing.
    #[test]
    fn enclosing_fn_is_the_innermost_brace_span() {
        let source = [
            "pub fn helper() \u{7b} builder(1); \u{7d}",
            "pub(in crate::voice) async fn gap_a() \u{7b} builder(2); \u{7d}",
            "#[inline] pub async fn gap_b() \u{7b} builder(3); \u{7d}",
            "pub const unsafe extern \"C\" fn outer(bytes: [u8; 2]) -> u8 \u{7b}",
            "    fn inner() \u{7b} builder(4); \u{7d}",
            "    builder(5);",
            "    0",
            "\u{7d}",
            "// fn commented() \u{7b} \u{7d}",
            "static KEY: u8 = builder(6);",
            "macro_rules! hidden \u{7b} () => \u{7b} fn in_macro() \u{7b} builder(7); \u{7d} \u{7d}; \u{7d}",
            "#[doc = \"https://sloga.gg\"] pub fn slashes() \u{7b} builder(8); \u{7d}",
            "pub fn literals() \u{7b} let _ = \"fn fake() \u{7b}\"; builder(9); \u{7d} // \u{7d}",
            "// macro_rules! named_only \u{7b}",
            "pub fn after_the_mention() \u{7b} builder(10); \u{7d}",
        ]
        .join("\n");
        let site = |n: u8| first(&source, &format!("builder({n})"));

        for (n, name) in [
            (1, "helper"),
            (2, "gap_a"),
            (3, "gap_b"),
            (4, "inner"),
            (5, "outer"),
            (8, "slashes"),
            (9, "literals"),
            (10, "after_the_mention"),
        ] {
            assert_eq!(enclosing_fn(&source, site(n)), name, "builder({n})");
        }
        for n in [6, 7] {
            let at = site(n);
            assert!(
                std::panic::catch_unwind(|| enclosing_fn(&source, at)).is_err(),
                "builder({n}) must fail closed"
            );
        }
    }

    /// The span `(open, close)` of the innermost block opened by exactly
    /// `header` (which ends in its opening brace) that contains byte `at`:
    /// `open` is the brace, `close` the byte just past its partner.
    fn block_around(shipping: &str, at: usize, header: &str) -> Option<(usize, usize)> {
        shipping
            .match_indices(header)
            .map(|(start, _)| start + header.len() - 1)
            .filter(|open| *open < at)
            .map(|open| (open, open + braced_body(shipping, open).len() + 2))
            .filter(|(_, close)| at < *close)
            .max_by_key(|(open, _)| *open)
    }

    /// The trimmed line holding byte `at`.
    fn line_at(shipping: &str, at: usize) -> &str {
        let start = shipping[..at].rfind('\n').map_or(0, |nl| nl + 1);
        let end = shipping[at..]
            .find('\n')
            .map_or(shipping.len(), |nl| at + nl);
        shipping[start..end].trim()
    }

    /// Every non-comment shipping line in the workspace that contains
    /// `needle`, as (crates/-relative path, trimmed line).
    fn shipping_lines_with(needle: &str) -> Vec<(String, String)> {
        let mut found = Vec::new();
        for (rel, shipping) in shipping_sources() {
            for line in shipping.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("//") && trimmed.contains(needle) {
                    found.push((rel.clone(), trimmed.to_string()));
                }
            }
        }
        found
    }

    /// Merge slice SEC2-6 (B5/B6), amended by media-e2ee S6M-2,
    /// workspace-wide: `drop_voice_participant_session(` (the one per-user
    /// delete of a session record) has exactly TWO shipping callers, both
    /// kicks that drop the record BEFORE their removal, each anchored in its
    /// own file by brace span (so neither file's anchor can vouch for the
    /// other's call):
    ///
    /// - `join_call` (`voice_join.rs`, fn `call`): once, inside the
    ///   `force_disconnect` block's kick loop, as the loop's guarded step;
    /// - the disconnect in `member_edit.rs` (fn `edit`): once, the exact
    ///   statement, inside the `remove: ["VoiceChannel"]` block's gated
    ///   source block, after every recorded-connections read there and
    ///   before every remote-control release and eviction there.
    ///
    /// A leave, a teardown, the ingress, crond or any other route that
    /// dropped a user's record would lose it across livekit's full reconnect
    /// (the next move then reaches nobody), or wipe a newer join's. Each site
    /// must be the whole line, so a trailing comment cannot stand in for it.
    /// Controls DROP-IN-LEAVE (a drop in `delete_voice_state`), VJ-NODROP-DB
    /// (the kick's drop deleted) and DROPLOOP (moved out of the kick loop);
    /// NODROP-DISC / DROPLATE-DISC on the disconnect, and DROP-NESTED (the
    /// disconnect's drop wrapped in `if holds_state`, media-e2ee S6RM-4): it
    /// must be a direct statement of the gated source block. Renamed from
    /// `only_join_calls_kick_drops_a_users_session_record`, whose single
    /// `join_call` anchor could not admit the disconnect's drop.
    #[test]
    fn a_session_record_is_dropped_only_by_a_kick_or_a_disconnect() {
        const VOICE_JOIN: &str = "delta/src/routes/channels/voice_join.rs";
        const KICK: &str = "if force_disconnect == Some(true) \u{7b}";
        const KICK_LOOP: &str =
            "for previous_channel in get_user_voice_channels(&user.id).await? \u{7b}";
        const KICK_DROP: &str = "if let Err(error) = \
             drop_voice_participant_session(&previous_channel.id, &user.id).await";
        const DISCONNECT: &str = "if remove.contains(&FieldsMember::VoiceChannel) \u{7b}";
        const SOURCE: &str = "if let Some(channel) = &source_id \u{7b}";
        const DISCONNECT_DROP: &str =
            "drop_voice_participant_session(channel, &target_user.id).await?;";

        let mut sites = Vec::new();
        for (rel, shipping) in shipping_sources() {
            for at in call_sites(&shipping, "drop_voice_participant_session(") {
                let within = enclosing_fn(&shipping, at);
                let line = line_at(&shipping, at);
                match (rel.as_str(), within.as_str()) {
                    (VOICE_JOIN, "call") => {
                        assert_eq!(line, KICK_DROP, "{rel}: the kick's drop, as written");
                        for block in [KICK, KICK_LOOP] {
                            assert!(
                                block_around(&shipping, at, block).is_some(),
                                "{rel} drops a session record outside `{block}`"
                            );
                        }
                    }
                    (MEMBER_EDIT, "edit") => {
                        assert_eq!(
                            line, DISCONNECT_DROP,
                            "{rel}: the disconnect's drop, as written"
                        );
                        assert!(
                            block_around(&shipping, at, DISCONNECT).is_some(),
                            "{rel} drops a session record outside `{DISCONNECT}`"
                        );
                        let (open, close) =
                            block_around(&shipping, at, SOURCE).unwrap_or_else(|| {
                                panic!("{rel} drops a session record outside `{SOURCE}`")
                            });
                        // Media-e2ee S6RM-4: a DIRECT statement of that block,
                        // at its own brace depth, never nested in a branch
                        // inside it (`if holds_state { ... }` would skip the
                        // drop for a target with no state there, while every
                        // placement check here still held). Merge slice
                        // S6F3A-2: counted on `blanked` text, so a brace in a
                        // string or char literal or in a comment (a string
                        // holding a closing brace ahead of the drop) cannot
                        // hide the nesting.
                        let code = blanked(&rel, &shipping, true);
                        let (mut depth, mut lowest) = (0i64, 0i64);
                        for ch in code[open + 1..at].chars() {
                            match ch {
                                '\u{7b}' => depth += 1,
                                '\u{7d}' => {
                                    depth -= 1;
                                    lowest = lowest.min(depth);
                                }
                                _ => {}
                            }
                        }
                        assert!(
                            depth == 0 && lowest == 0,
                            "{rel}: the disconnect's drop must be a direct statement of \
                             `{SOURCE}`, not nested in a block inside it (depth {depth})"
                        );
                        let inside = |needle: &str| -> Vec<usize> {
                            call_sites(&shipping, needle)
                                .into_iter()
                                .filter(|site| open < *site && *site < close)
                                .collect()
                        };
                        let reads = inside("recorded_voice_connections(");
                        assert!(
                            !reads.is_empty() && reads.iter().all(|read| *read < at),
                            "{rel}: the recorded connections are read before the drop"
                        );
                        for later in [
                            "release_remote_control_for_user(",
                            "remove_user_if_present_sids(",
                        ] {
                            let sites = inside(later);
                            assert!(
                                !sites.is_empty() && sites.iter().all(|site| at < *site),
                                "{rel}: the drop precedes every `{later}` of the disconnect"
                            );
                        }
                    }
                    _ => panic!(
                        "{rel} drops a user's session record (in `{within}`): only \
                         `join_call`'s kick and `member_edit`'s disconnect may"
                    ),
                }
                sites.push(format!("{rel}::{within}"));
            }
        }
        sites.sort();
        assert_eq!(
            sites,
            vec![
                format!("{VOICE_JOIN}::call"),
                format!("{MEMBER_EDIT}::edit")
            ],
            "exactly one drop in `join_call`'s kick and one in `member_edit`'s disconnect"
        );
    }

    /// Merge slice S6B-1 / M2C-6, workspace-wide: the session record has
    /// exactly its known writers in EVERY crate of the workspace, not only
    /// in delta (where `only_join_call_writes_a_session_record_in_this_crate`
    /// looks). Every shipping call site of the three record writers is
    /// counted and placed (file :: enclosing fn, by brace span):
    ///
    /// - `set_voice_participant_session(`: ONE, `join_call` (`voice_join.rs`
    ///   fn `call`), the join that admitted the session;
    /// - `carry_voice_participant_session(`: ONE, the move itself;
    /// - `drop_voice_participant_session(`: TWO, the kicks
    ///   (`a_session_record_is_dropped_only_by_a_kick_or_a_disconnect`).
    ///
    /// And the three NAMES appear in no other shipping code (comment lines
    /// aside): only as their definitions in this file, and as plain imports
    /// (`use`, never `as`) in the two route files that call them. So a
    /// writer behind an alias (`use ... as adopt`), a function pointer or a
    /// wrapper fails here too. A second writer anywhere (probe M2C6-GAP2: the
    /// AFK sweep "repairing" a missing owner from the user's first session,
    /// green at `80a15fab`) hands the next move to a session `join_call`
    /// never admitted: F1's shape.
    #[test]
    fn the_session_record_has_no_writer_but_the_known_ones() {
        const THIS: &str = "core/database/src/voice/mod.rs";
        const VOICE_JOIN: &str = "delta/src/routes/channels/voice_join.rs";
        const SET: &str = "set_voice_participant_session";
        const CARRY: &str = "carry_voice_participant_session";
        const DROP: &str = "drop_voice_participant_session";

        /// Whether the name at byte `at` sits in a plain `use` of it: the
        /// statement it is in starts with `use` (attribute and comment lines
        /// aside), and the name is followed by `,`, `;` or the group's
        /// closing brace, never by `as`.
        fn plain_import(shipping: &str, at: usize, name: &str) -> bool {
            let statement = shipping[..at].rfind(';').map_or(0, |semi| semi + 1);
            let head = shipping[statement..at]
                .lines()
                .map(str::trim)
                .filter(|line| {
                    !line.is_empty() && !line.starts_with("//") && !line.starts_with("#[")
                })
                .collect::<Vec<_>>()
                .join(" ");
            let after = shipping[at + name.len()..].trim_start();
            ["use ", "pub use ", "pub(crate) use "]
                .iter()
                .any(|form| head.starts_with(form))
                && after.starts_with(|ch: char| matches!(ch, ',' | ';' | '\u{7d}'))
        }

        let (mut calls, mut definitions, mut imports) = (Vec::new(), Vec::new(), Vec::new());
        for (rel, shipping) in shipping_sources() {
            for name in [SET, CARRY, DROP] {
                let called = call_sites(&shipping, &format!("{name}("));
                for (at, _) in shipping.match_indices(name) {
                    let line_start = shipping[..at].rfind('\n').map_or(0, |nl| nl + 1);
                    let before = shipping[line_start..at].trim_start();
                    if before.starts_with("//") {
                        continue;
                    }
                    if called.contains(&at) {
                        calls.push(format!("{name}: {rel}::{}", enclosing_fn(&shipping, at)));
                    } else if before == "pub async fn "
                        && shipping[at + name.len()..].starts_with('(')
                    {
                        definitions.push(format!("{name}: {rel}"));
                    } else if plain_import(&shipping, at, name) {
                        imports.push(format!("{name}: {rel}"));
                    } else {
                        panic!(
                            "{rel} names `{name}` outside a call, its definition or a plain \
                             import (an alias, a function pointer, a wrapper?): {}",
                            line_at(&shipping, at)
                        );
                    }
                }
            }
        }

        let sorted = |mut list: Vec<String>| {
            list.sort();
            list
        };
        let expected = |list: &[(&str, &str)]| {
            sorted(
                list.iter()
                    .map(|(name, place)| format!("{name}: {place}"))
                    .collect(),
            )
        };
        let (join, disconnect, the_move) = (
            format!("{VOICE_JOIN}::call"),
            format!("{MEMBER_EDIT}::edit"),
            format!("{THIS}::move_user_to_voice_channel_expecting"),
        );
        assert_eq!(
            sorted(calls),
            expected(&[
                (SET, join.as_str()),
                (CARRY, the_move.as_str()),
                (DROP, join.as_str()),
                (DROP, disconnect.as_str()),
            ]),
            "the session record's writers, workspace-wide, by call site"
        );
        assert_eq!(
            sorted(definitions),
            expected(&[(SET, THIS), (CARRY, THIS), (DROP, THIS)]),
            "each writer is defined once, here"
        );
        assert_eq!(
            sorted(imports),
            expected(&[(SET, VOICE_JOIN), (DROP, VOICE_JOIN), (DROP, MEMBER_EDIT)]),
            "each writer is imported only by the route that calls it"
        );
    }

    /// Merge slice SEC2-6 (B6/R8), workspace-wide: the session hash
    /// (`voice_session:{channel}`) is deleted WHOLE only with the call
    /// (`delete_channel_voice_state`, and the reconcile sweep for a dead
    /// room), and nothing else builds its key: `voice_session_key(` is
    /// called only by the record helpers and `delete_channel_voice_state`
    /// in this file, and by `reconcile.rs`'s sweep; the key literal exists
    /// once, in the builder. So no teardown anywhere (a leave's script
    /// included, which could only spell the key by hand) touches a record.
    /// Controls LEAVE (a `voice_session:` HDEL in the teardown script) and
    /// KEY-ELSEWHERE (the key built in the ingress's `api.rs`).
    ///
    /// Merge slice S6B-2 / RRB-3: every site is placed by BRACE SPAN
    /// (`enclosing_fn`) and counted EXACTLY per helper (and per reconcile
    /// fn), never as a de-duplicated set of names, so a second builder
    /// whose header the old textual read could not see, or a second site
    /// inside a listed helper, changes the multiset. Controls RRB3-GAP-A
    /// (a `pub(in crate::voice)` builder) and RRB3-GAP-B (an `#[inline]`
    /// builder wired into the ingress leave), both green before.
    #[test]
    fn the_session_hash_is_dropped_only_with_the_call() {
        const THIS: &str = "core/database/src/voice/mod.rs";
        const RECONCILE: &str = "daemons/voice-ingress/src/reconcile.rs";
        // `get_voice_participant_session` reads through
        // `get_voice_participant_session_seat` (merge slice RRB-1), which is
        // the one reader that builds the key. The carry builds it twice: the
        // source's and the destination's.
        const HELPERS: [(&str, usize); 5] = [
            ("set_voice_participant_session", 1),
            ("drop_voice_participant_session", 1),
            ("get_voice_participant_session_seat", 1),
            ("carry_voice_participant_session", 2),
            ("delete_channel_voice_state", 1),
        ];

        let (mut here, mut reconcile) = (Vec::new(), Vec::new());
        for (rel, shipping) in shipping_sources() {
            for at in call_sites(&shipping, "voice_session_key(") {
                let within = enclosing_fn(&shipping, at);
                match rel.as_str() {
                    THIS => here.push(within),
                    RECONCILE => reconcile.push(within),
                    _ => panic!(
                        "{rel} builds the session key (in `{within}`): only the record \
                         helpers, the call's own teardown and the reconcile sweep may"
                    ),
                }
            }
        }
        here.sort();
        let mut expected: Vec<String> = HELPERS
            .iter()
            .flat_map(|(helper, sites)| std::iter::repeat(helper.to_string()).take(*sites))
            .collect();
        expected.sort();
        assert_eq!(
            here, expected,
            "in this file only the record helpers and the call's teardown build the key, \
             each exactly as often as listed"
        );
        assert_eq!(
            reconcile,
            vec!["sweep".to_string(), "sweep".to_string()],
            "the reconcile sweep builds the key exactly twice, one per dead-call delete list"
        );

        let shipping = this_file_shipping();
        let teardown = flat_fn_body(&shipping, "pub async fn delete_channel_voice_state(");
        assert!(
            teardown.contains(".del(voice_session_key(&channel.id))"),
            "the call's teardown drops the whole hash: {teardown}"
        );

        let literals = shipping_lines_with("voice_session:");
        assert_eq!(
            literals,
            vec![(
                THIS.to_string(),
                "format!(\"voice_session:\u{7b}channel_id\u{7d}\")".to_string()
            )],
            "the session key is spelled out only by its builder"
        );
    }

    /// Merge slice M2B-8: the move admission key is built only by the two
    /// functions that write and peek it (`write_move_admission`,
    /// `peek_move_admission`), and the key literal only by its builder, so
    /// nothing else can grant, read or consume an admission. Control
    /// ADMIT-KEY-SET (`set_move_admission` writing the key itself).
    #[test]
    fn only_the_admission_writer_and_peek_build_the_admission_key() {
        let mut users = Vec::new();
        for (rel, shipping) in shipping_sources() {
            for at in call_sites(&shipping, "move_admission_key(") {
                users.push(format!("{rel}::{}", enclosing_fn(&shipping, at)));
            }
        }
        users.sort();
        assert_eq!(
            users,
            vec![
                "core/database/src/voice/mod.rs::peek_move_admission".to_string(),
                "core/database/src/voice/mod.rs::write_move_admission".to_string(),
            ],
            "only the admission's writer and its peek may build its key"
        );

        let literals = shipping_lines_with("move_admit:");
        assert_eq!(
            literals,
            vec![(
                "core/database/src/voice/mod.rs".to_string(),
                "format!(\"move_admit:\u{7b}user_id\u{7d}:\u{7b}channel_id\u{7d}\")".to_string()
            )],
            "the admission key is spelled out only by its builder"
        );
    }

    /// Merge slice P2A-10 / F8: whether anybody can be told about the move
    /// is known from `expected_session` alone, so it is decided right after
    /// the expected-source check, and a SWEEP with no owner is refused there,
    /// before admission and before anything is written (control SWEEP-NONE;
    /// the sweep itself skips such a member before calling, ruling
    /// 09-27). `expected_session` is read there and nowhere else.
    ///
    /// Merge slice SEC2-2 / B4: right after it, a SELF-move is refused
    /// `NotAuthenticated` unless its request session is that owner (no owner
    /// included), still after `AlreadyPresent` and the expected-source check
    /// and before admission, the SFU and any write (control SELF-OWNER).
    #[test]
    fn the_move_decides_nobody_right_after_the_expected_source() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        const DECIDED: &str = "if source_moved_on(expected_from, &from) \u{7b} \
             return Ok(VoiceMoveOutcome::NotConnected); \u{7d} \
             let owner = expected_session.filter(|session_id| !session_id.is_empty()); \
             if owner.is_none() && policy == MovePolicy::Sweep \u{7b} \
             return Err(create_error!(InvalidOperation)); \u{7d} \
             if let MovePolicy::SelfMove \u{7b} request_session \u{7d} = policy \u{7b} \
             if !self_move_from_owning_session(owner, request_session) \u{7b} \
             return Err(create_error!(NotAuthenticated)); \u{7d} \u{7d} \
             let VoiceMoveAdmission \u{7b} permissions \u{7d} = \
             admit_voice_move(db, target, destination, policy).await?;";
        assert_eq!(flat.matches(DECIDED).count(), 1, "{flat}");
        assert_eq!(
            flat.matches("expected_session").count(),
            1,
            "`expected_session` must be read once, into `owner`: {flat}"
        );
        assert_eq!(
            flat.matches("self_move_from_owning_session(").count(),
            1,
            "the owner check runs once, in the move itself: {flat}"
        );
    }

    /// Merge slice F9 / R14: the media-E2EE flag is read INSIDE the move,
    /// once, through the one helper that checks BOTH flags; the move takes no
    /// `bool` and no device from its caller, and hands no literal to
    /// `qualified_move_device`. Merge slice S6B-3: the one binding is the
    /// only one (no shadowing, no `mut`), and it is the exact third argument
    /// of the one `qualified_move_device(` call and used nowhere else.
    /// Control F9-SHADOW (`let media_e2ee = media_e2ee || true;` right after
    /// the read, green before).
    #[test]
    fn the_move_reads_the_media_e2ee_flag_itself() {
        let shipping = this_file_shipping();
        let helper = flat_fn_body(&shipping, "pub async fn media_e2ee_enabled(");
        assert!(
            helper.contains("features.e2ee_enabled && features.media_e2ee_enabled"),
            "the helper must check both flags: {helper}"
        );

        let definition = first(
            &shipping,
            "pub async fn move_user_to_voice_channel_expecting(",
        );
        let signature = &shipping
            [definition..definition + first(&shipping[definition..], "-> Result<VoiceMoveOutcome>")];
        for banned in ["bool", "device"] {
            assert!(
                !signature.contains(banned),
                "the move takes no `{banned}` parameter: {signature}"
            );
        }

        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            flat.matches("let media_e2ee = media_e2ee_enabled().await;").count(),
            1,
            "{flat}"
        );
        assert_eq!(flat.matches("media_e2ee_enabled()").count(), 1, "{flat}");
        assert_eq!(flat.matches("let media_e2ee").count(), 1, "{flat}");
        assert_eq!(flat.matches("let mut media_e2ee").count(), 0, "{flat}");
        assert_eq!(flat.matches("qualified_move_device(").count(), 1, "{flat}");
        const ARGUMENT: &str =
            "letdevice=qualified_move_device(&moving.identity,&target.id,media_e2ee);";
        let squeezed: String = flat.split_whitespace().collect();
        assert_eq!(
            squeezed.matches(ARGUMENT).count(),
            1,
            "the flag as read is the exact third argument: {flat}"
        );
        // The identifier occurs exactly twice: its binding and that
        // argument. A shadowing, a reassignment or a second use adds one.
        let is_ident = |ch: char| ch.is_alphanumeric() || ch == '_';
        let uses = flat
            .match_indices("media_e2ee")
            .filter(|(at, word)| {
                !flat[..*at].chars().next_back().is_some_and(is_ident)
                    && !flat[at + word.len()..].chars().next().is_some_and(is_ident)
            })
            .count();
        assert_eq!(uses, 2, "`media_e2ee`: one binding, one use: {flat}");
        assert!(
            first(&flat, "let media_e2ee") < first(&flat, "qualified_move_device("),
            "{flat}"
        );
        for literal in [", true)", ", false)"] {
            let calls = flat.match_indices("qualified_move_device(").map(|(at, _)| {
                let end = at + first(&flat[at..], ")") + 1;
                &flat[at..end]
            });
            for call in calls {
                assert!(!call.ends_with(literal), "a literal media-E2EE flag: {call}");
            }
        }
    }

    /// Merge slice RT-3 / P2A-16: the move and the route's pre-flight admit
    /// under the SAME caller-supplied policy, so a pre-flight can never
    /// accept what the move then refuses after the member was written.
    #[test]
    fn the_move_and_its_preflight_admit_under_the_same_policy() {
        const ADMIT: &str = "admit_voice_move(db, target, destination, policy)";

        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(flat.matches("admit_voice_move(").count(), 1, "{flat}");
        assert_eq!(flat.matches(ADMIT).count(), 1, "{flat}");

        let shipping = this_file_shipping();
        let preflight = flat_fn_body(&shipping, "pub async fn assert_voice_move_admissible(");
        assert_eq!(preflight.matches("admit_voice_move(").count(), 1, "{preflight}");
        assert_eq!(preflight.matches(ADMIT).count(), 1, "{preflight}");
        let definition = first(&shipping, "pub async fn assert_voice_move_admissible(");
        let signature = &shipping[definition..definition + first(&shipping[definition..], ")")];
        assert!(signature.contains("policy: MovePolicy"), "{signature}");
    }

    /// Merge slice P2A-3 / M2B-1: a move whose owning session can only be
    /// told WITHOUT a token (its client must `join_call`) is refused BEFORE
    /// the first write when `join_call` would refuse the target: no Connect
    /// on the destination, or its occupancy cap reached without
    /// `ManageChannel` (`join_call`'s own rule, read against the
    /// destination's roster), instead of evicting the target into nowhere
    /// under a 200. Controls NOREFUSE (the whole refusal deleted) and NOCAP
    /// (the occupancy half deleted).
    #[test]
    fn a_tokenless_move_without_connect_is_refused_before_any_write() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        let may = first(
            &flat,
            "let target_may_connect = \
             permissions.has_channel_permission(ChannelPermission::Connect);",
        );
        const TOKENLESS: &str = "if plan.session.is_some() && plan.mint.is_none() \u{7b}";
        assert_eq!(flat.matches(TOKENLESS).count(), 1, "{flat}");
        let tokenless = first(&flat, TOKENLESS);
        let (arm, _) = block_after(&flat, tokenless);
        for needle in [
            "let max_users = destination.voice().and_then(|voice| voice.max_users);",
            "Some(_) => get_voice_channel_members(&destination_channel).await?,",
            "None => None,",
            "if !target_may_connect || join_call_occupancy_refuses( roster.as_deref(), \
             max_users, permissions.has(ChannelPermission::ManageChannel as u64), ) \u{7b} \
             return Ok(VoiceMoveOutcome::TargetCannotJoin); \u{7d}",
        ] {
            assert!(
                arm.contains(needle),
                "the tokenless arm must ask `join_call`'s own admission (`{needle}`): {arm}"
            );
        }
        assert!(
            first(&flat, "let plan = move_token_plan(&delivery);") < tokenless
                && may < tokenless
                && tokenless < first(&flat, "carry_voice_participant_session("),
            "decided from the plan, before the first write: {flat}"
        );
    }

    /// Merge slice M2B-1: `join_call_occupancy_refuses` is `join_call`'s own
    /// occupancy rule, by value (no already-present exemption, unlike
    /// `occupancy_cap_refuses`; `ManageChannel` exempts; no cap or no roster
    /// is never full), AND the join route asks exactly that rule, through
    /// the helper, exactly once. The inline expression the rule was taken
    /// from (the join route's own until merge slice RRB-5) is refused, not
    /// accepted as an alternative (merge slice M2C-4 / S6B-5), so it can
    /// come back neither beside nor instead of the call, and the move cannot
    /// drift from what `join_call` answers.
    #[test]
    fn the_tokenless_move_asks_join_calls_own_occupancy_rule() {
        use super::join_call_occupancy_refuses as refuses;

        let full = vec!["A".to_string(), "B".to_string()];
        assert!(refuses(Some(&full), Some(2), false), "at the cap");
        assert!(refuses(Some(&full), Some(1), false), "over the cap");
        assert!(!refuses(Some(&full), Some(3), false), "a seat left");
        assert!(
            !refuses(Some(&full), Some(2), true),
            "ManageChannel exempts"
        );
        assert!(!refuses(Some(&full), None, false), "no cap");
        assert!(!refuses(None, Some(1), false), "no roster recorded");
        assert!(
            refuses(Some(&full), Some(2), false)
                && !super::occupancy_cap_refuses(&full, 2, "A", false),
            "no already-present exemption: `join_call` counts a stale roster entry of the \
             joiner itself, and so does the rule that predicts it"
        );

        const VOICE_JOIN: &str = "delta/src/routes/channels/voice_join.rs";
        let sources = shipping_sources();
        let join = &sources
            .iter()
            .find(|(rel, _)| rel == VOICE_JOIN)
            .unwrap_or_else(|| panic!("{VOICE_JOIN} left the workspace"))
            .1;
        let squeezed: String = join.split_whitespace().collect();
        const INLINE: &str = "ifget_voice_channel_members(&user_voice_channel).await?\
             .zip(voice_info.max_users)\
             .is_some_and(|(ms,max_users)|ms.len()>=max_users)\
             &&!current_permissions.has(ChannelPermission::ManageChannelasu64)\u{7b}\
             returnErr(create_error!(CannotJoinCall));\u{7d}";
        let inline = squeezed.matches(INLINE).count();
        let helper = squeezed.matches("join_call_occupancy_refuses(").count();
        assert_eq!(
            (inline, helper),
            (0, 1),
            "{VOICE_JOIN} must apply the rule through `join_call_occupancy_refuses` exactly \
             once, and never as the inline expression it was taken from (inline {inline}, \
             helper {helper})"
        );
    }

    /// Merge slice P2A-4 / P2A-5: the admission key the voice-ingress D-3
    /// re-check honours is written for a move the target could not have
    /// joined themselves, in the owner arm only, AFTER the owner re-check and
    /// BEFORE the `moved_to` label, and its failure fails the move (`?`): it
    /// is the one mandatory write, where the label stays best-effort (the
    /// M4-a pin above).
    #[test]
    fn the_move_writes_the_admission_key_before_the_marker() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        assert_eq!(flat.matches("set_move_admission(").count(), 1, "{flat}");
        let gate = first(
            &flat,
            "if needs_move_admission(policy, target_may_connect) \u{7b}",
        );
        let (gated, _) = block_after(&flat, gate);
        assert!(
            gated.contains("set_move_admission(&target.id, destination.id(), identity).await?;"),
            "the key write is mandatory and names the target and the destination: {gated}"
        );

        let matched = first(&flat, "match plan.session \u{7b}");
        let some_at = matched + first(&flat[matched..], "Some(session_id) => \u{7b}");
        let (some_arm, _) = block_after(&flat, some_at);
        assert!(
            some_arm.contains("set_move_admission("),
            "only a move somebody is told about is admitted: {some_arm}"
        );
        assert!(
            first(&flat, "voice_participant_record_is(") < gate
                && gate < first(&flat, "set_user_moved_to_voice("),
            "re-check < admission key < marker: {flat}"
        );
    }

    /// Media-e2ee S6M-3, placed by S6RM-1 / S6R-1: for a DEVICE token the
    /// move re-reads the device's identity row after the mint, and refuses
    /// unless it is still bound to the planned session. The binding the
    /// delivery was planned on is read before the carry, the room, the
    /// release and the mint (up to five SFU calls); a device revoked or
    /// re-bound in that window would otherwise still be handed its token.
    ///
    /// Pinned: once, a top-level statement IMMEDIATELY BEFORE the owner
    /// re-check (nothing between them), for the minted `token_device` only,
    /// deciding through `device_binding_still_holds` with the planned
    /// session, refusing `NotConnected` with no SFU call and no publish. And
    /// the owner re-check is the LAST statement before `match plan.session`
    /// (nothing between the end of its refusal block and that `match`), so
    /// it is the last read before the publish and only the admission key and
    /// the marker (Redis writes) are left between them; the re-read, a
    /// database round trip, used to sit in that window (S6F-2's placement).
    /// So the order is `.create_token(` < binding re-read < owner re-check <
    /// admission key < marker < publish, and the WC-1 window (no SFU call
    /// between the mint and the emit) still holds.
    ///
    /// Controls: REREAD (the re-read deleted) fails here and in
    /// `a_device_revoked_or_rebound_after_the_plan_refuses_the_move`;
    /// REREAD-LATE (the re-read moved back after the re-check) fails here.
    /// Renamed from
    /// `the_move_re_reads_the_device_binding_right_after_the_owner_re_check`,
    /// which stated the old order.
    #[test]
    fn the_move_re_reads_the_device_binding_right_before_the_owner_re_check() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        const RECHECK: &str =
            "if !voice_participant_record_is(&from, &target.id, plan.session, &owner_seat)\
             .await? \u{7b}";
        const REREAD: &str = "if let Some(Some(token_device)) = plan.mint \u{7b} \
             let bound_session = fetch_device_identity(db, &target.id, token_device) \
             .await? .map(|row| row.last_session_id); \
             if !device_binding_still_holds(plan.session, bound_session.as_deref()) \u{7b}";
        assert_eq!(flat.matches(REREAD).count(), 1, "{flat}");
        assert_eq!(flat.matches(RECHECK).count(), 1, "{flat}");
        assert_eq!(
            flat.matches("device_binding_still_holds(").count(),
            1,
            "{flat}"
        );

        let mint = first(&flat, ".create_token(");
        let reread = first(&flat, REREAD);
        let recheck = first(&flat, RECHECK);
        let matched = first(&flat, "match plan.session \u{7b}");
        assert!(
            mint < reread && reread < recheck && recheck < matched,
            "`.create_token(` < binding re-read < owner re-check < `match plan.session`: {flat}"
        );
        assert_eq!(depth_at(&flat, reread), 0, "a top-level statement: {flat}");

        let (block, reread_end) = block_after(&flat, reread);
        assert_eq!(
            flat[reread_end..recheck].trim(),
            "",
            "the binding re-read comes immediately before the owner re-check: {flat}"
        );
        let (_, recheck_end) = block_after(&flat, recheck);
        assert_eq!(
            flat[recheck_end..matched].trim(),
            "",
            "the owner re-check is the last statement before `match plan.session`, so \
             nothing but the Redis writes of the Some arm lies between it and the publish: \
             {flat}"
        );

        let (refusal, _) = block_after(block, first(block, "if !device_binding_still_holds("));
        assert!(
            refusal
                .trim()
                .ends_with("return Ok(VoiceMoveOutcome::NotConnected);"),
            "a binding that no longer holds refuses the move: {refusal}"
        );
        for banned in ["voice_client.", "remote_control::", ".private"] {
            assert!(
                !block.contains(banned),
                "the re-read calls no SFU and publishes nothing (`{banned}`): {block}"
            );
        }

        let admission = first(&flat, "set_move_admission(");
        let marker = first(&flat, "set_user_moved_to_voice(");
        assert!(
            matched < admission && admission < marker && marker < first(&flat, ".private_session("),
            "mint < binding re-read < re-check < admission key < marker < publish: {flat}"
        );
    }

    /// Media-e2ee S6M-3, by value: a device token is handed over only while
    /// the device's row still names exactly the planned session.
    #[test]
    fn the_device_binding_holds_only_for_the_planned_session() {
        use super::device_binding_still_holds as holds;

        assert!(holds(Some("S"), Some("S")), "still bound to the owner");
        assert!(
            !holds(Some("S"), Some("OTHER")),
            "re-bound to another session"
        );
        assert!(!holds(Some("S"), None), "revoked: no identity row");
        assert!(!holds(None, Some("S")), "no planned session");
        assert!(!holds(None, None), "nothing planned, nothing bound");
        assert!(
            !holds(Some(""), Some("")),
            "an empty session matches nothing"
        );
    }

    // ---- the delivery rules by value (ported from voice-move's route,
    // `f62a9c06` member_edit.rs, into the database crate: merge slice RB-H1;
    // by recorded seat kind since merge slice RRB-1) ----

    fn device_seat(device_id: &str) -> super::SeatKind {
        super::SeatKind::Device(device_id.to_string())
    }

    /// `move_event_delivery`'s `bare_seat_chosen`, spelled out: the
    /// connection the move chose is the target's bare seat, or it is not
    /// (a device seat, whether or not media E2EE qualifies its device).
    const BARE_CHOSEN: bool = true;
    const OTHER_CHOSEN: bool = false;

    /// B2: a device-qualified token goes only to the session the device is
    /// bound to, and only for the device the owner was recorded as seated
    /// as, which must be the chosen connection's device.
    #[test]
    fn a_device_qualified_move_token_goes_to_the_bound_session_only() {
        use super::{move_event_delivery, MoveDelivery};

        let session = |session_id: &str, device_id: Option<&str>| MoveDelivery::Session {
            session_id: session_id.to_string(),
            device_id: device_id.map(str::to_string),
        };
        let no_token = |session_id: &str| MoveDelivery::SessionNoToken {
            session_id: session_id.to_string(),
        };
        let dev = device_seat("dev");

        assert_eq!(
            move_event_delivery(
                Some("bound"),
                &dev,
                Some("dev"),
                OTHER_CHOSEN,
                Some("bound")
            ),
            session("bound", Some("dev")),
            "seated as the chosen device, recorded session = bound session: the device token"
        );
        assert_eq!(
            move_event_delivery(Some("web"), &dev, Some("dev"), OTHER_CHOSEN, Some("bound")),
            no_token("web"),
            "recorded session != bound session: the recorded one, no token"
        );
        assert_eq!(
            move_event_delivery(Some("bound"), &dev, Some(""), OTHER_CHOSEN, Some("bound")),
            no_token("bound"),
            "empty device suffix with a bound session: fails closed"
        );
        assert_eq!(
            move_event_delivery(Some("bound"), &dev, Some("dev"), OTHER_CHOSEN, None),
            no_token("bound"),
            "no identity row (never registered, or revoked): no token"
        );
        assert_eq!(
            move_event_delivery(Some("bound"), &dev, Some("dev"), OTHER_CHOSEN, Some("")),
            no_token("bound"),
            "no bound session: no token"
        );
        assert_eq!(
            move_event_delivery(Some("bound"), &dev, Some(""), OTHER_CHOSEN, None),
            no_token("bound"),
            "empty device suffix: fails closed"
        );
        assert_eq!(
            move_event_delivery(
                Some("bound"),
                &device_seat(""),
                Some(""),
                OTHER_CHOSEN,
                Some("bound")
            ),
            no_token("bound"),
            "an empty recorded device: fails closed"
        );
    }

    /// Merge slice RRB-1 (the operator's ruling, Option A), by value: the
    /// move mints EXACTLY the seat kind recorded with the owner at its join,
    /// and only for the connection it chose. A device-seated owner gets a
    /// token for its recorded device only, when that is the device the move
    /// addresses; never one for another device bound to it, and never a
    /// bare token. A bare-seated owner gets a bare token when the move chose
    /// its BARE seat, even when its session is bound to a device of the
    /// target (the RRB-1 case, a SessionNoToken before the ruling), so the
    /// moderator rules and the sweep apply to it; with a device seat chosen
    /// instead it is told with no token (merge slice SEC4-1: these rows
    /// said "bare whichever seat is chosen" before, which handed a bare
    /// token to a client the SFU lists as a device). An unknown seat kind (a
    /// record from before the seat kind) is told with no token, whatever is
    /// chosen. Controls MINT-BARE, UNKNOWN-BARE, OTHER-DEVICE and
    /// BARE-ANYSEAT fail here.
    #[test]
    fn a_move_mints_exactly_the_recorded_seat_kind() {
        use super::{move_event_delivery, MoveDelivery, SeatKind};

        let bare_token = |session_id: &str| MoveDelivery::Session {
            session_id: session_id.to_string(),
            device_id: None,
        };
        let device_token = |session_id: &str, device_id: &str| MoveDelivery::Session {
            session_id: session_id.to_string(),
            device_id: Some(device_id.to_string()),
        };
        let no_token = |session_id: &str| MoveDelivery::SessionNoToken {
            session_id: session_id.to_string(),
        };

        // Seated as D1.
        assert_eq!(
            move_event_delivery(
                Some("desktop"),
                &device_seat("D1"),
                Some("D1"),
                OTHER_CHOSEN,
                Some("desktop")
            ),
            device_token("desktop", "D1"),
            "its own device seat, bound to it: that device's token"
        );
        assert_eq!(
            move_event_delivery(
                Some("desktop"),
                &device_seat("D1"),
                Some("D0"),
                OTHER_CHOSEN,
                Some("desktop")
            ),
            no_token("desktop"),
            "another device's seat chosen, bound to the owner too: no token, never D0's"
        );
        for bound in [None, Some("desktop"), Some("web")] {
            for chosen in [BARE_CHOSEN, OTHER_CHOSEN] {
                assert_eq!(
                    move_event_delivery(Some("desktop"), &device_seat("D1"), None, chosen, bound),
                    no_token("desktop"),
                    "a bare seat chosen (or media E2EE off), row {bound:?}, bare chosen \
                     {chosen}: never a bare token"
                );
            }
        }

        // Seated bare, the bare seat chosen: the bare token, whatever the
        // session is bound to.
        for bound in [None, Some("desktop"), Some("web")] {
            assert_eq!(
                move_event_delivery(Some("desktop"), &SeatKind::Bare, None, BARE_CHOSEN, bound),
                bare_token("desktop"),
                "seated bare, its bare seat chosen ({bound:?}): the bare token"
            );
        }
        // Seated bare, a DEVICE seat chosen (the owner's bare seat is not
        // listed; the device qualified under media E2EE or not): no token
        // (SEC4-1), whatever the device is bound to. Flipped from "the bare
        // token whichever seat is chosen".
        for (device, bound) in [
            (None, None),
            (None, Some("desktop")),
            (Some("D1"), Some("desktop")),
            (Some("D1"), Some("web")),
            (Some("D1"), None),
        ] {
            assert_eq!(
                move_event_delivery(
                    Some("desktop"),
                    &SeatKind::Bare,
                    device,
                    OTHER_CHOSEN,
                    bound
                ),
                no_token("desktop"),
                "seated bare, a device seat chosen ({device:?}, {bound:?}): no token"
            );
        }

        // Seat kind unknown.
        for (device, bound) in [
            (None, None),
            (None, Some("desktop")),
            (Some("D1"), Some("desktop")),
            (Some("D1"), None),
        ] {
            for chosen in [BARE_CHOSEN, OTHER_CHOSEN] {
                assert_eq!(
                    move_event_delivery(Some("desktop"), &SeatKind::Unknown, device, chosen, bound),
                    no_token("desktop"),
                    "seat kind unknown ({device:?}, {bound:?}, bare chosen {chosen}): no token"
                );
            }
        }

        // No owner is nobody, whatever the seat kind says.
        for seat in [device_seat("D1"), SeatKind::Bare, SeatKind::Unknown] {
            assert_eq!(
                move_event_delivery(None, &seat, Some("D1"), OTHER_CHOSEN, Some("desktop")),
                MoveDelivery::Nobody,
                "{seat:?}"
            );
            assert_eq!(
                move_event_delivery(Some(""), &seat, None, BARE_CHOSEN, None),
                MoveDelivery::Nobody,
                "{seat:?}"
            );
        }
    }

    /// Media-e2ee final audit F1: two BARE sessions of one user. Only the
    /// session that owns the participant is told to move; the one it kicked
    /// never hears about it.
    #[test]
    fn a_move_reaches_only_the_session_that_owns_the_participant() {
        use super::{move_event_delivery, MoveDelivery, SeatKind};

        assert_eq!(
            move_event_delivery(Some("web"), &SeatKind::Bare, None, BARE_CHOSEN, None),
            MoveDelivery::Session {
                session_id: "web".to_string(),
                device_id: None,
            },
            "bare identity: a bare token to the recorded session only"
        );
        assert_eq!(
            move_event_delivery(
                Some("web"),
                &SeatKind::Bare,
                None,
                BARE_CHOSEN,
                Some("desktop")
            ),
            MoveDelivery::Session {
                session_id: "web".to_string(),
                device_id: None,
            },
            "bare identity: an identity row of another device changes nothing"
        );

        for seat in [SeatKind::Bare, device_seat("dev"), SeatKind::Unknown] {
            for (device, bound) in [
                (None, None),
                (None, Some("desktop")),
                (Some("dev"), Some("desktop")),
                (Some("dev"), None),
                (Some(""), None),
            ] {
                for chosen in [BARE_CHOSEN, OTHER_CHOSEN] {
                    assert_eq!(
                        move_event_delivery(None, &seat, device, chosen, bound),
                        MoveDelivery::Nobody,
                        "no recorded session ({seat:?}, {device:?}, {chosen}, {bound:?}): \
                         nobody is told"
                    );
                    assert_eq!(
                        move_event_delivery(Some(""), &seat, device, chosen, bound),
                        MoveDelivery::Nobody,
                        "an empty recorded session ({seat:?}, {device:?}, {chosen}, \
                         {bound:?}): nobody"
                    );
                }
            }
        }
    }

    /// Merge slice RRB-1 (which replaced SEC2-3's "bound to any device"
    /// predicate), keeping its security intent: an owner SEATED as its
    /// device never gets a BARE token (its own device seat was not the one
    /// listed, a sibling's bare seat was): it is told with no token and
    /// joins through `join_call` as its device. Its own device seat still
    /// gets its device token, and a bare-seated owner the bare one for its
    /// bare seat.
    #[test]
    fn a_device_seated_owner_never_gets_a_bare_token() {
        use super::{move_event_delivery, MoveDelivery, SeatKind};

        assert_eq!(
            move_event_delivery(
                Some("desktop"),
                &device_seat("dev"),
                None,
                BARE_CHOSEN,
                None
            ),
            MoveDelivery::SessionNoToken {
                session_id: "desktop".to_string(),
            },
            "a bare seat chosen, the owner seated as a device: told, no token"
        );
        assert_eq!(
            move_event_delivery(
                Some("desktop"),
                &device_seat("dev"),
                None,
                BARE_CHOSEN,
                Some("desktop")
            ),
            MoveDelivery::SessionNoToken {
                session_id: "desktop".to_string(),
            },
            "a bare seat stays tokenless whatever the (irrelevant) row says"
        );
        assert_eq!(
            move_event_delivery(
                Some("desktop"),
                &device_seat("dev"),
                Some("dev"),
                OTHER_CHOSEN,
                Some("desktop")
            ),
            MoveDelivery::Session {
                session_id: "desktop".to_string(),
                device_id: Some("dev".to_string()),
            },
            "its own device seat: the device token, as before"
        );
        assert_eq!(
            move_event_delivery(Some("web"), &SeatKind::Bare, None, BARE_CHOSEN, None),
            MoveDelivery::Session {
                session_id: "web".to_string(),
                device_id: None,
            },
            "an owner seated bare, its bare seat chosen: the bare token, as before"
        );
    }

    /// Merge slice RRB-1: the seat kind the move uses is the record's only
    /// when the record names the owner the caller passed; a record naming
    /// another session, or none, or no owner, is unknown (the carry-over
    /// then refuses such a move).
    #[test]
    fn the_owner_seat_kind_is_read_only_from_its_own_record() {
        use super::{owner_recorded_seat, SeatKind};

        let record = |session_id: &str, seat: SeatKind| Some((session_id.to_string(), seat));

        assert_eq!(
            owner_recorded_seat(Some("S"), record("S", device_seat("D1"))),
            device_seat("D1")
        );
        assert_eq!(
            owner_recorded_seat(Some("S"), record("S", SeatKind::Bare)),
            SeatKind::Bare
        );
        assert_eq!(
            owner_recorded_seat(Some("S"), record("S", SeatKind::Unknown)),
            SeatKind::Unknown
        );
        for (owner, stored, why) in [
            (
                Some("S"),
                record("T", SeatKind::Bare),
                "another session's record",
            ),
            (
                Some("S"),
                record("SX", device_seat("D1")),
                "a longer session id",
            ),
            (Some("S"), None, "no record"),
            (None, record("S", SeatKind::Bare), "no owner"),
            (Some(""), record("", SeatKind::Bare), "an empty owner"),
        ] {
            assert_eq!(
                owner_recorded_seat(owner, stored),
                SeatKind::Unknown,
                "{why}"
            );
        }
    }

    /// Merge slice RRB-1: the stored form of a session record, by value. The
    /// session is everything before the first separator, so a compare of the
    /// session part is exact; a device id keeps any character; the old form
    /// (the session alone) and anything unreadable are unknown; an empty
    /// session is no record.
    #[test]
    fn the_session_record_stores_the_seat_kind() {
        use super::{parse_voice_session_record, voice_session_record, SeatKind};

        for (seat, stored) in [
            (device_seat("D1"), "01SESSION|d:D1"),
            (device_seat("a:b|c"), "01SESSION|d:a:b|c"),
            (SeatKind::Bare, "01SESSION|b"),
            (SeatKind::Unknown, "01SESSION"),
        ] {
            assert_eq!(voice_session_record("01SESSION", &seat), stored);
            assert_eq!(
                parse_voice_session_record(stored),
                Some(("01SESSION".to_string(), seat.clone())),
                "{stored}"
            );
        }
        for stored in [
            "01SESSION|d:",
            "01SESSION|",
            "01SESSION|x",
            "01SESSION|bare",
            "01SESSION|B",
        ] {
            assert_eq!(
                parse_voice_session_record(stored),
                Some(("01SESSION".to_string(), SeatKind::Unknown)),
                "{stored}: unreadable, so unknown"
            );
        }
        for stored in ["", "|b", "|d:D1", "|"] {
            assert_eq!(
                parse_voice_session_record(stored),
                None,
                "{stored:?}: no session"
            );
        }
    }

    /// Merge slice F12 / M2B-7 / RRB-1: which listed seat is the OWNER's:
    /// the seat of the kind recorded with it. Its recorded device's seat,
    /// not the smallest bound one; its bare seat, ahead of a sibling's
    /// device seat; nothing for an unknown seat kind or a recorded seat that
    /// is not listed. Legs and other users never count. Control SEAT-PREF
    /// fails here.
    #[test]
    fn the_owner_seat_is_the_seat_recorded_at_its_join() {
        use super::{owner_listed_seat, SeatKind};

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let d1 = format!("{user}:D1");
        let d2 = format!("{user}:D2");
        let listing = [
            listed(&d2, 3_000, Some("N-D2")),
            listed(&d1, 1_000, None),
            listed(user, 2_000, None),
            listed(&format!("{user}::screen"), 4_000, Some("N-LEG")),
            listed("01KX7HASD9FHBYA3XGKA5YACYZ", 5_000, Some("N-OTHER")),
        ];

        assert_eq!(
            owner_listed_seat(&listing, user, &device_seat("D2")).as_deref(),
            Some(d2.as_str()),
            "the recorded device's seat, not the smaller D1"
        );
        assert_eq!(
            owner_listed_seat(&listing, user, &device_seat("D1")).as_deref(),
            Some(d1.as_str())
        );
        assert_eq!(
            owner_listed_seat(&listing, user, &SeatKind::Bare).as_deref(),
            Some(user),
            "seated bare: the bare seat, not a sibling's device seat"
        );
        assert_eq!(
            owner_listed_seat(&listing, user, &device_seat("D9")),
            None,
            "the recorded device is not listed: the bare seat is not its own"
        );
        assert_eq!(
            owner_listed_seat(&listing[..2], user, &SeatKind::Bare),
            None,
            "no bare seat listed: nothing is the owner's"
        );
        assert_eq!(
            owner_listed_seat(&listing, user, &SeatKind::Unknown),
            None,
            "seat kind unknown"
        );
        assert_eq!(
            owner_listed_seat(&listing, user, &device_seat("")),
            None,
            "an empty device"
        );
        assert_eq!(
            owner_listed_seat(&listing, user, &device_seat(":screen")),
            None,
            "a leg is never the owner's seat"
        );
    }

    /// The move mints and publishes from this plan alone, so these pin
    /// which device a move token is minted for and which session gets it.
    #[test]
    fn a_move_token_plan_pins_the_minted_device_and_the_topic() {
        use super::{move_token_plan, MoveDelivery, MoveTokenPlan};

        let session = MoveDelivery::Session {
            session_id: "bound".to_string(),
            device_id: Some("dev".to_string()),
        };
        let plan = move_token_plan(&session);
        assert_eq!(
            plan.mint,
            Some(Some("dev")),
            "session delivery: the token is minted for the device"
        );
        assert_eq!(
            plan.session,
            Some("bound"),
            "session delivery: published to the bound session only"
        );
        assert_eq!(
            plan,
            MoveTokenPlan {
                mint: Some(Some("dev")),
                session: Some("bound"),
            }
        );

        let bare = MoveDelivery::Session {
            session_id: "web".to_string(),
            device_id: None,
        };
        assert_eq!(
            move_token_plan(&bare),
            MoveTokenPlan {
                mint: Some(None),
                session: Some("web"),
            },
            "bare delivery: a bare token, to the recorded session only"
        );

        let no_token = MoveDelivery::SessionNoToken {
            session_id: "web".to_string(),
        };
        assert_eq!(
            move_token_plan(&no_token),
            MoveTokenPlan {
                mint: None,
                session: Some("web"),
            },
            "no-token delivery: nothing is minted, one session is told"
        );

        assert_eq!(
            move_token_plan(&MoveDelivery::Nobody),
            MoveTokenPlan {
                mint: None,
                session: None,
            },
            "no owner: nothing is minted and nothing is published"
        );
    }

    /// The topic each plan publishes on, as `EventV1::private_session` builds
    /// it from `plan.session`: one session's topic, never the user's
    /// (`{user}!`, which every session of the user reads).
    #[test]
    fn a_move_plan_publishes_on_one_session_topic() {
        use super::{move_token_plan, MoveDelivery};
        use crate::events::client::session_topic;

        let topic = |delivery: &MoveDelivery| move_token_plan(delivery).session.map(session_topic);

        for delivery in [
            MoveDelivery::Session {
                session_id: "bound".to_string(),
                device_id: Some("dev".to_string()),
            },
            MoveDelivery::Session {
                session_id: "bound".to_string(),
                device_id: None,
            },
            MoveDelivery::SessionNoToken {
                session_id: "bound".to_string(),
            },
        ] {
            assert_eq!(
                topic(&delivery).as_deref(),
                Some("session:bound"),
                "{delivery:?}: the owning session's topic only"
            );
        }
        assert_eq!(
            topic(&MoveDelivery::Nobody),
            None,
            "no owner: no topic at all"
        );
    }

    #[test]
    fn a_move_mints_a_qualified_identity_only_with_media_e2ee_on() {
        use super::qualified_move_device;

        let user = "01USER0000000000000000000A";
        let qualified = format!("{user}:{}", "ab".repeat(16));
        let device = "ab".repeat(16);

        assert_eq!(
            qualified_move_device(&qualified, user, true),
            Some(device.as_str())
        );
        assert_eq!(qualified_move_device(user, user, true), None, "bare");
        assert_eq!(
            qualified_move_device(&qualified, user, false),
            None,
            "media E2EE off: the move takes the bare path, as join_call only \
             admits bare identities then"
        );
        assert_eq!(
            qualified_move_device(&format!("{user}X:dev"), user, true),
            None,
            "a longer user id sharing the prefix is not this user's device"
        );
        assert_eq!(
            qualified_move_device(&format!("{user}:"), user, true),
            Some(""),
            "an empty suffix stays qualified, so it fails closed"
        );
    }

    /// Lane 6a2: a self-move goes ahead only from the session that owns the
    /// participant in the source channel, which is the one the move event
    /// goes to and the one that obeys it.
    #[test]
    fn a_self_move_must_come_from_the_session_that_owns_the_participant() {
        use super::self_move_from_owning_session;

        assert!(
            self_move_from_owning_session(Some("desktop"), Some("desktop")),
            "the owning session may move itself"
        );

        for (recorded, request, why) in [
            (Some("desktop"), Some("web"), "a sibling session"),
            (Some("desktop"), None, "no session (a bot)"),
            (None, Some("desktop"), "no record: the owner is unknown"),
            (None, None, "no record and no session"),
            (Some(""), Some(""), "an empty id matches nothing"),
            (Some(""), Some("web"), "an empty record"),
            (Some("desktop"), Some(""), "an empty session id"),
        ] {
            assert!(
                !self_move_from_owning_session(recorded, request),
                "{}: must be refused",
                why
            );
        }
    }

    /// Merge slice F12, the nonce rule by value: the event names the chosen
    /// connection only when the plan mints for exactly that connection's
    /// device, which the delivery allows only for the session the device is
    /// bound to. A bare seat, an unbound device, a tokenless or ownerless
    /// plan, or media E2EE off (the plan then mints bare): both omitted.
    #[test]
    fn the_event_names_the_connection_only_when_proven_the_owners() {
        use super::{owner_addressing, MoveAddressing, MoveTokenPlan};

        let named = |device: Option<&str>| MoveAddressing {
            device_id: device.map(str::to_string),
            conn_nonce: Some("N".to_string()),
        };
        let omitted = MoveAddressing {
            device_id: None,
            conn_nonce: None,
        };
        let plan = |mint: Option<Option<&'static str>>, session: Option<&'static str>| {
            MoveTokenPlan { mint, session }
        };

        assert_eq!(
            owner_addressing(&plan(Some(Some("D1")), Some("S")), &named(Some("D1"))),
            named(Some("D1")),
            "minted for this connection's device, for its bound session: named"
        );
        for (why, plan, addressing) in [
            ("a bare seat", plan(Some(None), Some("S")), named(None)),
            (
                "media E2EE off: a bare token for a device seat",
                plan(Some(None), Some("S")),
                named(Some("D1")),
            ),
            (
                "the owner is not the device's session: no token",
                plan(None, Some("S")),
                named(Some("D1")),
            ),
            ("nobody", plan(None, None), named(Some("D1"))),
            (
                "minted for another device than the connection's",
                plan(Some(Some("D2")), Some("S")),
                named(Some("D1")),
            ),
        ] {
            assert_eq!(owner_addressing(&plan, &addressing), omitted, "{why}");
        }
    }

    /// Merge slice P2A-4: the admission key is written exactly for a move a
    /// moderator or the sweep makes of a target without Connect. A self-move
    /// never writes it (it needs Connect to be admitted), and a target with
    /// Connect needs none.
    #[test]
    fn the_move_admission_is_written_only_for_a_target_who_could_not_join() {
        use super::{needs_move_admission, MovePolicy};

        let self_move = MovePolicy::SelfMove {
            request_session: Some("S"),
        };
        assert!(needs_move_admission(MovePolicy::Moderator, false));
        assert!(needs_move_admission(MovePolicy::Sweep, false));
        assert!(!needs_move_admission(self_move, false));
        for policy in [MovePolicy::Moderator, MovePolicy::Sweep, self_move] {
            assert!(!needs_move_admission(policy, true), "{policy:?} with Connect");
        }
    }

    /// Merge slice P2A-4: the key outlives the move token by at least five
    /// seconds of slack and expires before the sweep's 30 s per-member move
    /// claim (`AFK_MOVE_CLAIM_TTL_SECS`, crond). It is written with that
    /// lifetime, under one key builder, and PEEKED (a plain GET) by the
    /// re-check, never drained (control ADMIT-DRAIN).
    #[test]
    fn the_move_admission_key_outlives_the_token() {
        use super::{MOVE_ADMISSION_TTL_SECS, MOVE_TOKEN_TTL};

        assert!(MOVE_ADMISSION_TTL_SECS as u64 >= MOVE_TOKEN_TTL.as_secs() + 5);
        assert!(MOVE_ADMISSION_TTL_SECS < 30);
        assert_eq!(
            super::move_admission_key("U", "C"),
            "move_admit:U:C",
            "the key the deploy ACL allows"
        );

        let shipping = this_file_shipping();
        let set = flat_fn_body(&shipping, "async fn set_move_admission(");
        assert!(
            set.contains(
                "write_move_admission(user_id, channel_id, identity, MOVE_ADMISSION_TTL_SECS)"
            ),
            "{set}"
        );
        let write = flat_fn_body(&shipping, "async fn write_move_admission(");
        assert!(
            write.contains(".set_ex(move_admission_key(user_id, channel_id), identity, ttl_secs)"),
            "{write}"
        );
        let peek = flat_fn_body(&shipping, "async fn peek_move_admission(");
        assert!(
            peek.contains(".get(move_admission_key(user_id, channel_id))")
                && !peek.contains("get_del")
                && !peek.contains(".del("),
            "the re-check peeks and never drains: {peek}"
        );
        let recheck = flat_fn_body(&shipping, "pub async fn voice_connect_still_allowed(");
        assert!(
            recheck.contains(
                "Ok(peek_move_admission(user_id, channel_id).await?.as_deref() == Some(identity))"
            ),
            "the admission is the exact joining identity (control ADMIT-ANYID): {recheck}"
        );
    }

    /// The identity the admission key names is the one `create_token` mints
    /// for the same device: `{user}` bare, `{user}:{device}` qualified. Held
    /// to `create_token`'s own text, so the two cannot drift.
    #[test]
    fn the_admitted_identity_is_the_one_the_token_carries() {
        use super::move_token_identity;

        assert_eq!(move_token_identity("U", None), "U");
        assert_eq!(move_token_identity("U", Some("D1")), "U:D1");

        const FILE: &str = "core/database/src/voice/voice_client.rs";
        let shipping = shipping_sources()
            .into_iter()
            .find(|(rel, _)| rel == FILE)
            .expect("voice_client.rs is not in the workspace scan")
            .1;
        let mint = flat_fn_body(&shipping, "pub async fn create_token(");
        assert!(
            mint.contains(
                "let identity = match device_id \u{7b} Some(device_id) => \
                 format!(\"\u{7b}\u{7d}:\u{7b}\u{7d}\", user.id, device_id), \
                 None => user.id.clone(), \u{7d};"
            ),
            "`create_token` builds the identity the admission key mirrors: {mint}"
        );
    }

    // ---- the room-wide permission sync (AFK Stage 6 F-A1) ----

    /// What a room-wide sync's outcomes amount to: every member synced or
    /// gone is `Ok`; any failure fails it, and the FIRST failure is the one
    /// returned, however many follow.
    #[test]
    fn member_sync_result_skips_the_gone_and_returns_the_first_failure() {
        use super::{member_sync_result, MemberSync};

        assert_eq!(member_sync_result::<&str>([]), Ok(()));
        assert_eq!(
            member_sync_result::<&str>([MemberSync::Synced, MemberSync::Synced]),
            Ok(()),
            "all synced"
        );
        assert_eq!(
            member_sync_result([
                MemberSync::Gone("user deleted"),
                MemberSync::Synced,
                MemberSync::Gone("not in the room"),
            ]),
            Ok(()),
            "a member who has gone is skipped, not an error"
        );
        assert_eq!(
            member_sync_result([
                MemberSync::Synced,
                MemberSync::Failed("first 500"),
                MemberSync::Gone("not in the room"),
                MemberSync::Failed("second 500"),
                MemberSync::Synced,
            ]),
            Err("first 500"),
            "the FIRST real failure wins"
        );
    }

    /// The loop half, driven through the SAME `sync_each_member`
    /// `sync_voice_permissions` uses, with a fake per-member sync: a failure
    /// on member 1 still pushes members 2, 3 and 4, in order, and a gone
    /// member in between changes nothing.
    #[tokio::test]
    async fn a_failed_member_does_not_stop_the_room_sync() {
        use super::{member_sync_result, sync_each_member, MemberSync};

        let pushed = std::sync::Mutex::new(Vec::new());
        let members = ["m1", "m2", "m3", "m4"].map(str::to_string).to_vec();

        let outcomes = sync_each_member("room", members, |user_id: String| {
            pushed.lock().unwrap().push(user_id.clone());
            async move {
                match user_id.as_str() {
                    "m1" => MemberSync::Failed("m1 500"),
                    "m2" => MemberSync::Gone("m2 not in the room"),
                    "m3" => MemberSync::Failed("m3 500"),
                    _ => MemberSync::Synced,
                }
            }
        })
        .await;

        assert_eq!(
            *pushed.lock().unwrap(),
            ["m1", "m2", "m3", "m4"],
            "every member must be tried, in order, whatever the one before \
             it did — F-A1: an early return leaves every later member with \
             a grant that no longer matches the server"
        );
        assert_eq!(
            outcomes,
            vec![
                MemberSync::Failed("m1 500"),
                MemberSync::Gone("m2 not in the room"),
                MemberSync::Failed("m3 500"),
                MemberSync::Synced,
            ]
        );
        assert_eq!(member_sync_result(outcomes), Err("m1 500"));
    }

    /// The shipping half: `sync_voice_permissions` walks the room through
    /// `sync_each_member` with no `?` on the per-member call and hands every
    /// outcome to `member_sync_result`; `sync_each_member`'s loop has no
    /// exit; and the two ways a member is gone (the user, then the member
    /// document or the SFU participant) are classified at the step that
    /// finds them out. Mutations: the old `for … ?` loop restored, an exit
    /// added to the loop, the result decided by anything else, or either
    /// `Gone` arm turned into a failure.
    ///
    /// S-3 D-4 (lane B1) retargeted the call shape: the per-member call now
    /// carries the member's share of the room's ONE listing, and the push is
    /// `update_permissions_connections` over every listed connection instead
    /// of the mapping-resolving `update_permissions_if_present`. The S-3
    /// cleanup deleted that method, so the ban on it here went vacuous; it
    /// is retargeted at the mapping itself (`voice_participant_identity(`,
    /// which covers both the raw and the falling-back reader).
    #[test]
    fn the_room_sync_tries_every_member_before_deciding() {
        let shipping = this_file_shipping();

        const WALK: &str = "let outcomes = sync_each_member(channel.id(), members, move |user_id| \
             \u{7b} let connections = roster.remove(&user_id).unwrap_or_default(); async move \
             \u{7b} let connections = if listing_failed \u{7b} SyncConnections::Unlisted \u{7d} \
             else \u{7b} SyncConnections::Listed(&connections) \u{7d}; \
             sync_member_voice_permissions( db, voice_client, node, &user_id, connections, \
             channel, server, role_id, ) .await \u{7d} \u{7d}) .await;";
        let room = flat_fn_body(&shipping, "pub async fn sync_voice_permissions(");
        assert!(
            room.contains(WALK),
            "`sync_voice_permissions` must walk the room through `sync_each_member`, \
             with no `?` on the per-member call: {room}"
        );
        assert!(
            room.ends_with(
                &(WALK.to_string()
                    + " match listing_error \u{7b} Some(error) => Err(error), None => \
                       member_sync_result(outcomes), \u{7d}")
            ),
            "every outcome must go to `member_sync_result`, and its answer is the \
             function's, unless the room's listing failed, whose error is then the \
             answer, AFTER every member: {room}"
        );
        // S-3 B1-R: a failed listing does not end the room before its members
        // (their roster flags are still written); it is recorded, not `?`d.
        assert!(
            room.contains("Err(error) => (BTreeMap::new(), Some(error)),"),
            "{room}"
        );
        assert!(
            first(&room, ".list_participants_reported(") < first(&room, "sync_each_member("),
            "{room}"
        );
        assert_eq!(
            room.matches("return").count(),
            1,
            "the no-node exit only: {room}"
        );
        assert!(
            !room.contains("sync_user_voice_permissions("),
            "the room sync must not call the single-user entry point, whose \
             `Err` for a gone member would fail the room: {room}"
        );

        let each = flat_fn_body(&shipping, "async fn sync_each_member<");
        let loop_at = first(&each, "for item in items");
        let loop_body = &each[loop_at..];
        for exit in [".await?", ")?", "return", "break"] {
            assert!(
                !loop_body.contains(exit),
                "the room-sync loop contains `{exit}`: {loop_body}"
            );
        }
        assert!(loop_body.contains("outcomes.push(outcome);"), "{loop_body}");

        let one = flat_fn_body(&shipping, "async fn sync_member_voice_permissions(");
        assert!(
            one.contains(
                "Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) \
                 => \u{7b} return MemberSync::Gone(error) \u{7d}"
            ),
            "a deleted user is skipped: {one}"
        );

        let push = flat_fn_body(&shipping, "async fn push_user_voice_permissions(");
        assert!(
            push.contains(
                "Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) \
                 => \u{7b} return Ok(MemberSync::Gone(error)) \u{7d}"
            ),
            "a deleted member is skipped: {push}"
        );
        assert!(
            push.contains(
                "let pushed = voice_client .update_permissions_connections( node, channel_id, \
                 connections, voice_participant_permissions(can_listen, &allowed_sources), ) \
                 .await?; if !pushed \u{7b} return Ok(MemberSync::Gone(create_error!(InternalError))); \u{7d}"
            ),
            "a participant the SFU no longer has is skipped: {push}"
        );
        assert!(
            !push.contains("voice_participant_identity("),
            "the sync must not resolve a connection through the identity mapping: {push}"
        );
        // D-4's outcome table: only NO connection at all ends the member
        // before the push; a stateless live connection goes on to be pushed.
        assert!(
            push.contains(
                "if connections.is_empty() \u{7b} return Ok(match voice_state \u{7b} None => \
                 MemberSync::Synced, Some(_) => MemberSync::Gone(create_error!(InternalError)), \
                 \u{7d}); \u{7d}"
            ),
            "{push}"
        );
        // The only early `Synced` exits: no state with nothing to push to,
        // and the room's failed listing (after the write).
        assert!(
            push.contains(
                "if voice_state.is_none() && matches!( connections, \
                 SyncConnections::Listed([]) | SyncConnections::Unlisted ) \u{7b} return \
                 Ok(MemberSync::Synced); \u{7d}"
            ),
            "{push}"
        );
        assert!(
            push.contains("SyncConnections::Unlisted => return Ok(MemberSync::Synced),"),
            "{push}"
        );
        assert_eq!(
            push.matches("return Ok(MemberSync::Synced)").count(),
            2,
            "{push}"
        );
        assert!(
            first(&push, "if connections.is_empty()")
                < first(&push, ".update_permissions_connections("),
            "{push}"
        );
        // S-3 B1-R: the roster-flag write precedes EVERY SFU contact, the
        // single-user listing included, and the event follows the push.
        let write = first(
            &push,
            "update_voice_state(&user_voice_channel, &user.id, &update_event)",
        );
        assert!(
            write < first(&push, ".list_participants_reported("),
            "{push}"
        );
        assert!(
            write < first(&push, ".update_permissions_connections("),
            "{push}"
        );
        assert!(
            first(&push, ".update_permissions_connections(")
                < first(&push, "EventV1::UserVoiceStateUpdate"),
            "{push}"
        );
    }

    /// RA-5 (Stage 6 re-audit): the single-user entry point answers a gone
    /// member with the error it always returned, and LOGS it first: the
    /// SFU-not-found `InternalError` is built without `to_internal_error()`,
    /// so nothing else would. Mutations: the log deleted, or the arm merged
    /// back into the silent `Gone | Failed` one.
    #[test]
    fn the_single_user_sync_logs_a_gone_member() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn sync_user_voice_permissions(");

        assert!(
            body.contains("MemberSync::Gone(error) => \u{7b} log::warn!("),
            "a gone member must be logged: {body}"
        );
        let gone = first(&body, "MemberSync::Gone(error) => \u{7b} log::warn!(");
        assert!(
            body[gone..].contains("user.id, channel.id(), error.error_type ); Err(error) \u{7d}"),
            "the log names the user and the channel, then the old error is returned: {body}"
        );
        assert!(
            body.contains("MemberSync::Failed(error) => Err(error),"),
            "{body}"
        );
    }

    /// S-3 D-6: the server-wide sync is the room sync's own loop over the
    /// server's channels (no second loop to drift), and each channel checks
    /// its node pin BEFORE any database read, fetches by id (never
    /// `fetch_channels`, whose drivers disagree on missing ids), and counts a
    /// deleted channel as gone. Mutations: a `?` or an exit in the walk, the
    /// fetch moved above the node read, or the NotFound arm made a failure.
    #[test]
    fn the_server_sync_walks_every_channel_node_first() {
        let shipping = this_file_shipping();

        assert_eq!(
            flat_fn_body(&shipping, "pub async fn sync_server_voice_permissions("),
            "sync_server_channels(server, move |channel_id| async move \u{7b} \
             sync_server_channel_voice_permissions(db, voice_client, server, &channel_id, \
             role_id).await \u{7d}) .await"
        );
        assert_eq!(
            flat_fn_body(&shipping, "async fn sync_server_channels<"),
            "let outcomes = sync_each_member(&server.id, server.channels.clone(), sync_one).await; \
             member_sync_result(outcomes)"
        );

        let one = flat_fn_body(&shipping, "async fn sync_server_channel_voice_permissions(");
        assert!(
            one.starts_with(
                "match get_channel_node(channel_id).await \u{7b} Ok(Some(_)) => \u{7b}\u{7d} \
                 Ok(None) => return MemberSync::Synced, Err(error) => return \
                 MemberSync::Failed(error), \u{7d}"
            ),
            "the node pin is read first, and no call means no database read: {one}"
        );
        assert!(
            first(&one, "get_channel_node(") < first(&one, "db.fetch_channel(channel_id)"),
            "{one}"
        );
        assert!(!one.contains("fetch_channels("), "{one}");
        assert!(
            one.contains(
                "Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) \
                 => \u{7b} return MemberSync::Gone(error) \u{7d}"
            ),
            "a deleted channel is skipped, not a failure: {one}"
        );
        assert!(
            one.ends_with(
                "match sync_voice_permissions(db, voice_client, &channel, Some(server), \
                 role_id).await \u{7b} Ok(()) => MemberSync::Synced, Err(error) => \
                 MemberSync::Failed(error), \u{7d}"
            ),
            "{one}"
        );
    }

    /// S-3 D-2 as amended by WA-R / RA2-1, the removal's ORDER: the record
    /// is read BEFORE the SFU listing (read after, a sibling recorded in
    /// between looks stale and is deleted while live: WA-1), a failed
    /// eviction returns before any teardown, and the teardown is the SET
    /// delete of the sids this removal knows. No whole-user
    /// `delete_voice_state` in any of the three removal bodies: each decides
    /// from a listing. WB-2 split the failed eviction by what Redis holds:
    /// the error with something held, reported and Ok with nothing.
    /// Mutations: the record read moved below the listing, the set delete
    /// replaced by `delete_voice_state`, the held user's error swallowed,
    /// the WB-2 split reverted to an unconditional `?`. WBR-3 split it again
    /// by whether the room was listed (mutation: a `Listed` failure sent to
    /// the WB-2 report), and S6B-3 pins every release's
    /// `participant_already_gone: false` (mutation: any of them `true`).
    ///
    /// The S-3 cleanup moved the teardown into the shared
    /// `tear_down_removed_connections` (WB-8 adds its Leave there), which is
    /// scanned with the removal bodies, and retargeted the vacuous
    /// `.remove_user(` ban (the method is deleted) at the bool
    /// `remove_user_if_present(`, which cannot name the sids a set teardown
    /// needs.
    #[test]
    fn the_removal_reads_the_record_before_the_listing_and_deletes_only_what_it_knows() {
        let shipping = this_file_shipping();

        for definition in [
            "pub async fn remove_user_from_voice_channel(",
            "pub async fn remove_user_from_voice_channels(",
            "pub async fn remove_user_from_server_voice(",
            "pub async fn tear_down_removed_connections(",
        ] {
            let body = flat_fn_body(&shipping, definition);
            assert!(
                !body.contains("delete_voice_state("),
                "`{definition}` decides from a listing and must never run the whole-user \
                 teardown (WA-1): {body}"
            );
            assert!(
                !body.contains("remove_user_if_present("),
                "{definition}: {body}"
            );
        }

        let teardown = flat_fn_body(&shipping, "pub async fn tear_down_removed_connections(");
        assert!(
            teardown.starts_with(
                "let announced_by_webhook = evicted.as_ref().is_some_and(|sids| !sids.is_empty()); \
                 let leave = delete_voice_connections(channel, user_id, \
                 &removal_teardown_sids(evicted, recorded)) .await?;"
            ),
            "the teardown is the set delete of the known sids: {teardown}"
        );
        assert_eq!(
            teardown.matches("delete_voice_connections(").count(),
            1,
            "{teardown}"
        );

        let body = flat_fn_body(&shipping, "pub async fn remove_user_from_voice_channel(");
        assert!(
            first(&body, "recorded_voice_connections(")
                < first(&body, "remove_user_if_present_sids("),
            "ORDERING RULE: the record must be read before the SFU listing: {body}"
        );
        assert!(
            first(&body, "holds_voice_state_in(") < first(&body, "remove_user_if_present_sids("),
            "{body}"
        );
        assert!(
            body.starts_with(
                "let recorded: Vec<String> = recorded_voice_connections(channel, user_id) .await?"
            ),
            "the record is the first read, and a failed one aborts: {body}"
        );
        // WB-2: a failed eviction never reaches the teardown. With something
        // of the user in Redis it is the answer; with nothing, it is reported
        // and the channel answers Ok with no release and no script. WBR-3:
        // only when the room was never listed. A failed removal of a LISTED
        // connection is the answer whatever Redis holds, after the release
        // when nothing held made it run earlier.
        assert!(
            body.contains(
                "Some(node) => match voice_client .remove_user_if_present_sids(&node, user_id, \
                 &channel.id) .await \u{7b} Ok(evicted) => evicted, \
                 Err(EvictionFailure::Listed(error)) => \u{7b} if !holds_state \u{7b} \
                 remote_control::release_remote_control_for_user( db, voice_client, channel, \
                 user_id, \"participant_left\", false, ) .await; \u{7d} return Err(error); \u{7d} \
                 Err(EvictionFailure::Unlisted(error)) if holds_state => return Err(error), \
                 Err(EvictionFailure::Unlisted(error)) => \u{7b} \
                 report_unheld_eviction_failure(&channel.id, user_id, error); return Ok(()); \
                 \u{7d} \u{7d}, None => None, \u{7d};"
            ),
            "a failed eviction returns before any teardown: {body}"
        );
        // S6B-3: every release on this path revokes actively
        // (`participant_already_gone: false`): before the listing when Redis
        // holds the user, and after it (on success, or on a failed listed
        // removal) when only the listing does. `true` would end a grant
        // whose controller the eviction may have failed to remove, leaving
        // its `can_publish_data` with nothing able to revoke it (F-9).
        assert_eq!(
            body.matches(
                "release_remote_control_for_user( db, voice_client, channel, user_id, \
                 \"participant_left\", false, ) .await;"
            )
            .count(),
            3,
            "{body}"
        );
        assert_eq!(
            body.matches("release_remote_control_for_user(").count(),
            3,
            "{body}"
        );
        assert!(
            first(&body, "remove_user_if_present_sids(")
                < first(&body, "tear_down_removed_connections("),
            "{body}"
        );
        assert!(
            body.ends_with(
                "tear_down_removed_connections(channel, user_id, evicted, recorded).await?; Ok(())"
            ),
            "the teardown is the shared set delete of the known sids: {body}"
        );
        assert_eq!(
            body.matches("tear_down_removed_connections(").count(),
            1,
            "{body}"
        );
        assert!(!body.contains("delete_voice_connections("), "{body}");
        // P2-6 + RA2-1: the whole-channel skip needs all three: nothing in
        // Redis (record or state), and nothing listed.
        assert!(
            body.contains(
                "let holds_state = !recorded.is_empty() || holds_voice_state_in(channel, \
                 user_id).await?;"
            ),
            "{body}"
        );
        assert!(
            body.contains(
                "if !holds_state \u{7b} if evicted.as_ref().is_none_or(Vec::is_empty) \u{7b} \
                 return Ok(()); \u{7d}"
            ),
            "{body}"
        );
        // The skip above and the WB-2 arm: no other early success.
        assert_eq!(body.matches("return Ok(())").count(), 2, "{body}");
    }

    /// S-3 D-2: the removal walks never exit early. Every channel is tried,
    /// each outcome is recorded, and `member_sync_result` answers after all.
    /// The server walk takes the pointer BEFORE the channels (their
    /// teardowns delete it). Mutations: `?` on a per-channel removal, or an
    /// exit added to either walk.
    #[test]
    fn the_removal_walks_try_every_channel() {
        let shipping = this_file_shipping();

        let bots = flat_fn_body(&shipping, "pub async fn remove_user_from_voice_channels(");
        let walk = &bots[first(&bots, "for channel in channels")..];
        for exit in ["?", "return", "break"] {
            assert!(
                !walk.contains(exit),
                "`{exit}` in the bot removal walk: {walk}"
            );
        }
        assert!(
            walk.contains(
                "let removed = remove_user_from_voice_channel(db, voice_client, &channel, \
                 user_id).await; outcomes.push(removal_outcome(&channel.id, user_id, removed));"
            ),
            "{walk}"
        );
        assert!(bots.ends_with("member_sync_result(outcomes)"), "{bots}");

        let server = flat_fn_body(&shipping, "pub async fn remove_user_from_server_voice(");
        for exit in ["?", "return", "break"] {
            assert!(
                !server.contains(exit),
                "`{exit}` in the server removal: a failure would leave the later calls \
                 holding the user: {server}"
            );
        }
        assert!(
            first(&server, "get_user_voice_channel_in_server(")
                < first(&server, "for channel_id in &server.channels"),
            "{server}"
        );
        assert_eq!(
            server.matches("outcomes.push(removal_outcome(").count(),
            4,
            "every step records its outcome: {server}"
        );
        // P2-6: the pointer's channel is removed too, node or no node,
        // unless the walk already removed it.
        assert!(
            server.contains(
                "if let Some(channel_id) = pointed.filter(|id| \
                 !removed_from.contains(&id.as_str())) \u{7b}"
            ),
            "{server}"
        );
        assert!(server.ends_with("member_sync_result(outcomes)"), "{server}");
    }

    /// The two gone cases that need no Redis, end to end against the
    /// Reference driver: a user id with no user document, and a user with no
    /// member document in the server, are both `Gone` (skipped by the room
    /// sync), and the single-user entry point still answers them with the
    /// `NotFound` it always has. On the shared Redis-test runtime (see
    /// `tests::rt`).
    #[test]
    fn a_deleted_user_or_member_is_gone_not_failed() {
        super::tests::rt().block_on(a_deleted_user_or_member_is_gone_not_failed_case())
    }

    async fn a_deleted_user_or_member_is_gone_not_failed_case() {
        use super::{
            sync_member_voice_permissions, sync_user_voice_permissions, MemberSync,
            SyncConnections, VoiceClient,
        };
        use crate::{Channel, Database, Server, User};
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };
        use revolt_result::ErrorType;

        let db = Database::Reference(Default::default());
        let voice_client = VoiceClient::new(Default::default());

        let owner = User::create(&db, "SyncGoneOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "SyncGoneServer".to_string(),
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

        // No user document at all.
        match sync_member_voice_permissions(
            &db,
            &voice_client,
            "node",
            "01KX7HASD9FHBYA3XGKA5YACYX",
            SyncConnections::Listed(&[]),
            &channel,
            Some(&server),
            None,
        )
        .await
        {
            MemberSync::Gone(error) => {
                assert!(matches!(error.error_type, ErrorType::NotFound), "{error:?}")
            }
            other => panic!("a deleted user must be Gone, got {other:?}"),
        }

        // A user who is not (or no longer) a member of the server, even one
        // the SFU still lists (S-3 D-4): Gone at the member check, before any
        // push (this client has no node, so a push would be a failure).
        let stranger = User::create(&db, "SyncGoneStranger".to_string(), None, None)
            .await
            .expect("`User`");
        match sync_member_voice_permissions(
            &db,
            &voice_client,
            "node",
            &stranger.id,
            SyncConnections::Listed(&[format!("{}:D1", stranger.id)]),
            &channel,
            Some(&server),
            None,
        )
        .await
        {
            MemberSync::Gone(error) => {
                assert!(matches!(error.error_type, ErrorType::NotFound), "{error:?}")
            }
            other => panic!("a deleted member must be Gone, got {other:?}"),
        }

        let error = sync_user_voice_permissions(
            &db,
            &voice_client,
            "node",
            &stranger,
            &channel,
            Some(&server),
            None,
        )
        .await
        .expect_err("the single-user entry point keeps its error");
        assert!(matches!(error.error_type, ErrorType::NotFound), "{error:?}");
    }

    /// FU-1: what the two sides of a designation change amount to. Either
    /// side failing fails the change, the FIRST (outgoing) error wins when
    /// both fail, and a side that did not run changes nothing.
    #[test]
    fn designation_sync_result_returns_the_first_side_that_failed() {
        use super::designation_sync_result;

        assert_eq!(designation_sync_result::<&str>([]), Ok(()));
        assert_eq!(designation_sync_result::<&str>([Ok(()), Ok(())]), Ok(()));
        assert_eq!(
            designation_sync_result([Ok(()), Err("incoming")]),
            Err("incoming")
        );
        assert_eq!(
            designation_sync_result([Err("outgoing"), Ok(())]),
            Err("outgoing")
        );
        assert_eq!(
            designation_sync_result([Err("outgoing"), Err("incoming")]),
            Err("outgoing"),
            "the outgoing error is the first one"
        );
    }

    /// F-A1, the heal path: the INCOMING side of a designation change is
    /// unguarded, so re-sending the same `afk_channel_id` walks the room
    /// again; the OUTGOING side keeps its guard, because with the designation
    /// unchanged the outgoing channel IS the incoming one.
    ///
    /// FU-1: an outgoing failure no longer skips the incoming side. Both
    /// results are recorded, with no `?` on either sync call (nor anywhere
    /// else in the body: the resolve failure stays swallowed by `if let Ok`),
    /// the outgoing one first, and `designation_sync_result` decides.
    ///
    /// Mutations: the incoming side re-guarded on `previous != incoming`, the
    /// outgoing guard dropped, or `?` restored on the outgoing call.
    #[test]
    fn a_resent_designation_resyncs_the_incoming_room() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn sync_afk_designation_change(");
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`sync_afk_designation_change` lost `{needle}`: {body}"))
        };

        const OUTGOING: &str = "let outgoing = sync_voice_permissions(db, voice_client, &channel, \
             Some(server), None).await;";
        const INCOMING: &str = "if let Some(channel) = incoming_afk_channel \u{7b} \
             sides.push(sync_voice_permissions(db, voice_client, channel, Some(server), None).await); \
             \u{7d}";
        assert!(
            at(OUTGOING) < at("sides.push(outgoing);")
                && at("sides.push(outgoing);") < at(INCOMING),
            "the outgoing result is recorded, and only then the incoming side runs: {body}"
        );
        for exit in [".await?", ")?", "return"] {
            assert!(
                !body.contains(exit),
                "`{exit}` in the designation sync: an outgoing failure would skip the \
                 incoming side, and its occupants would keep publishing: {body}"
            );
        }
        assert!(
            body.ends_with("designation_sync_result(sides)"),
            "both sides' results decide the answer: {body}"
        );
        assert!(
            body.contains(
                "if let Some(previous) = previous_afk_channel_id \u{7b} \
                 if server.afk_channel_id.as_deref() != Some(previous) \u{7b}"
            ),
            "the outgoing side must stay guarded on the designation having moved: {body}"
        );
        assert_eq!(
            body.matches("sync_voice_permissions(").count(),
            2,
            "one sync per side: {body}"
        );
    }

    // ---- `delete_voice_state`: one script, one fallback ----
    //
    // What these cannot prove: that Redis executes the script as read. The
    // Redis-backed `delete_voice_state_keeps_per_server_state_after_a_move`
    // owns that, and it is compile-only on a box without Redis (owed to CI).

    /// A shipping function's braced body, comment lines dropped, with every
    /// run of whitespace collapsed to one space so a needle does not depend
    /// on line wrapping.
    fn flat_fn_body(shipping: &str, definition: &str) -> String {
        let at = shipping
            .find(definition)
            .unwrap_or_else(|| panic!("mod.rs no longer defines `{definition}`"));
        // Escaped brace: see `both_voice_state_teardowns_clear_the_identity_mapping`.
        let open = at + shipping[at..].find('\u{7b}').expect("a body");

        braced_body(shipping, open)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn this_file_shipping() -> String {
        const FILE: &str = "core/database/src/voice/mod.rs";

        shipping_sources()
            .into_iter()
            .find(|(rel, _)| rel == FILE)
            .expect("this very file is not in the workspace scan")
            .1
    }

    /// B-2: the script's Lua source, EXACTLY. Every line is a decision that a
    /// one-token edit reverses without failing anything else: the compare
    /// (`~=` keeps a newer channel's per-server state; `==` would keep it for
    /// the channel being left), the slot each command reads, and each
    /// per-channel delete. A literal copy on purpose: changing the script has
    /// to mean changing this, deliberately, alongside the layout test below.
    ///
    /// S-3 D-1 added the two modes in front of the teardown: `connection`
    /// (HDEL the sid, then a survivor of this user re-points the mapping and
    /// returns 2 with nothing torn down) and `user` (HDEL every entry of this
    /// user FIRST, no survivor branch, P2-10), plus the error reply for any
    /// other mode; and moved the flags from `KEYS[7..]` to `KEYS[8..]` to make
    /// room for `vc_conns:{channel}` at `KEYS[7]`. `unpack(KEYS, 7)` would now
    /// DEL the whole connection record of every user in the call.
    ///
    /// S-3 WA-R changed it again, deliberately: the `connections` (set) mode
    /// shares connection mode's loop and survivor scan (WA-1); the loop HDELs
    /// a sid only when its RECORDED identity is the user's, and in connection
    /// mode a foreign one is an error reply before any write (WA-6), with the
    /// connection mode held to exactly one sid so that stays true; the
    /// returns go through `answer`, which adds the skip counts in set mode
    /// only, so the two older modes still return a bare integer.
    #[test]
    fn delete_voice_state_script_source_is_pinned() {
        let expected = [
            "",
            "local prefix = ARGV[2] .. ':'",
            "local foreign = 0",
            "local unknown = 0",
            "local function answer(code)",
            "    if ARGV[4] == 'connections' then",
            "        return \u{7b}code, foreign, unknown\u{7d}",
            "    end",
            "    return code",
            "end",
            "if ARGV[4] == 'connection' and #ARGV ~= 5 then",
            "    return redis.error_reply('ERR voice state teardown: connection mode takes one sid')",
            "end",
            "if ARGV[4] == 'connection' or ARGV[4] == 'connections' then",
            "    for i = 5, #ARGV do",
            "        local identity = redis.call('HGET', KEYS[7], ARGV[i])",
            "        if not identity then",
            "            unknown = unknown + 1",
            "        elseif identity == ARGV[2] or string.sub(identity, 1, #prefix) == prefix then",
            "            redis.call('HDEL', KEYS[7], ARGV[i])",
            "        elseif ARGV[4] == 'connection' then",
            "            return redis.error_reply('ERR voice state teardown: foreign connection')",
            "        else",
            "            foreign = foreign + 1",
            "        end",
            "    end",
            "    local identities = redis.call('HVALS', KEYS[7])",
            "    for i = 1, #identities do",
            "        local identity = identities[i]",
            "        if identity == ARGV[2] or string.sub(identity, 1, #prefix) == prefix then",
            "            redis.call('HSET', KEYS[5], ARGV[2], identity)",
            "            return answer(2)",
            "        end",
            "    end",
            "elseif ARGV[4] == 'user' then",
            "    local entries = redis.call('HGETALL', KEYS[7])",
            "    for i = 1, #entries, 2 do",
            "        local identity = entries[i + 1]",
            "        if identity == ARGV[2] or string.sub(identity, 1, #prefix) == prefix then",
            "            redis.call('HDEL', KEYS[7], entries[i])",
            "        end",
            "    end",
            "else",
            "    return redis.error_reply('ERR voice state teardown: bad mode')",
            "end",
            "redis.call('SREM', KEYS[2], ARGV[2])",
            "redis.call('SREM', KEYS[3], ARGV[3])",
            "redis.call('HDEL', KEYS[4], ARGV[2])",
            "redis.call('HDEL', KEYS[5], ARGV[2])",
            "redis.call('DEL', KEYS[6])",
            "local pointer = redis.call('GET', KEYS[1])",
            "if pointer and pointer ~= ARGV[1] then",
            "    return answer(0)",
            "end",
            "redis.call('DEL', KEYS[1], unpack(KEYS, 8))",
            "return answer(1)",
            "",
        ]
        .join("\n");

        assert_eq!(
            super::DELETE_VOICE_STATE_LUA,
            expected,
            "the voice-state teardown script changed; if that is deliberate, \
             change this copy and the layout test with it"
        );
        assert!(
            this_file_shipping().contains("LazyLock::new(|| Script::new(DELETE_VOICE_STATE_LUA))"),
            "the static script must be built from the source pinned above"
        );
    }

    /// B-2: the script's `KEYS[]` and `ARGV[]`, by value, in the slots the
    /// Lua source reads. A wrong argument does not error — `ARGV[1]` set to
    /// the user id compares a channel id with a user id, never matches, and
    /// silently keeps every per-server key forever.
    #[test]
    fn delete_voice_state_script_input_is_pinned() {
        use super::{
            voice_state_teardown_input, ToRedisArgs, UserVoiceChannel, VoiceStateTeardownInput,
        };

        let channel = UserVoiceChannel {
            id: "CHAN".to_string(),
            server_id: Some("SRV".to_string()),
        };
        let strings =
            |items: &[&str]| -> Vec<String> { items.iter().map(|item| item.to_string()).collect() };

        assert_eq!(
            voice_state_teardown_input(&channel, "USER"),
            VoiceStateTeardownInput {
                keys: strings(&[
                    "USER:SRV",                    // KEYS[1], the pointer
                    "vc_members:CHAN",             // KEYS[2]
                    "vc:USER",                     // KEYS[3]
                    "vc_leg:CHAN",                 // KEYS[4]
                    "voice_identity:CHAN",         // KEYS[5]
                    "annotations_allow:CHAN:USER", // KEYS[6]
                    "vc_conns:CHAN",               // KEYS[7], per CHANNEL
                    "joined_at:USER:SRV",          // KEYS[8..], the flags
                    "is_publishing:USER:SRV",
                    "is_receiving:USER:SRV",
                    "screensharing:USER:SRV",
                    "camera:USER:SRV",
                    "screen_video:USER:SRV",
                    "recording:USER:SRV",
                    "rc_capable:USER:SRV",
                    "watching:USER:SRV",
                ]),
                // ARGV[1] the channel, ARGV[2] the user, ARGV[3] the `vc:`
                // member, ARGV[4] whole-user mode
                args: strings(&["CHAN", "USER", "CHAN-SRV", "user"]),
            }
        );

        // One connection's departure: the SAME keys, the mode switched and
        // the sid appended as ARGV[5]. A per-server connection key would read
        // "vc_conns:SRV" here and fail.
        let mut connection = voice_state_teardown_input(&channel, "USER");
        connection.args[3] = "connection".to_string();
        connection.args.push("SID".to_string());
        assert_eq!(
            super::voice_connection_teardown_input(&channel, "USER", "SID"),
            connection
        );
        assert_eq!(connection.keys[6], "vc_conns:CHAN");
        assert_eq!(
            connection.args.len(),
            5,
            "connection mode carries exactly one sid; the script refuses any other count"
        );

        // S-3 WA-R set mode: the SAME keys, the mode `connections`, and the
        // sids as ARGV[5..] in the order given. An empty set is the bare
        // four arguments, which the script reads as a survivor check.
        let mut set = voice_state_teardown_input(&channel, "USER");
        set.args[3] = "connections".to_string();
        set.args.extend(strings(&["S2", "S1"]));
        assert_eq!(
            super::voice_connections_teardown_input(&channel, "USER", &strings(&["S2", "S1"])),
            set
        );
        assert_eq!(
            super::voice_connections_teardown_input(&channel, "USER", &[]).args,
            strings(&["CHAN", "USER", "CHAN-SRV", "connections"])
        );

        // `ARGV[3]` must be the member `create_voice_state` SADDs into
        // `vc:{user}` byte for byte, or the SREM removes nothing.
        let input = voice_state_teardown_input(&channel, "USER");
        assert_eq!(
            channel.to_redis_args(),
            vec![input.args[2].as_bytes().to_vec()]
        );

        // No server (a DM or group call): the pointer and the flags key on the
        // channel itself, and `vc:` stores the bare channel id.
        let direct = UserVoiceChannel {
            id: "DM".to_string(),
            server_id: None,
        };
        let input = voice_state_teardown_input(&direct, "USER");
        assert_eq!(input.keys[0], "USER:DM");
        assert_eq!(input.keys[6], "vc_conns:DM");
        assert_eq!(input.keys[7], "joined_at:USER:DM");
        assert_eq!(input.args, strings(&["DM", "USER", "DM", "user"]));
    }

    /// S-3 D-1: the record script's source and its `KEYS[]` / `ARGV[]` by
    /// value. The answer is `SISMEMBER vc_members:{channel} user == 0` — the
    /// voice state — and NOT `HLEN == 1` (P2-1: a stale sid would make a real
    /// join invisible). The keys are per CHANNEL.
    #[test]
    fn record_voice_connection_script_is_pinned() {
        use super::{
            voice_connection_record_input, UserVoiceChannel, VoiceConnectionRecordInput,
            RECORD_VOICE_CONNECTION_LUA,
        };

        assert_eq!(
            RECORD_VOICE_CONNECTION_LUA,
            [
                "",
                "redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])",
                "if redis.call('SISMEMBER', KEYS[2], ARGV[3]) == 1 then",
                "    return 0",
                "end",
                "return 1",
                "",
            ]
            .join("\n")
        );
        assert!(
            this_file_shipping()
                .contains("LazyLock::new(|| Script::new(RECORD_VOICE_CONNECTION_LUA))"),
            "the static record script must be built from the source pinned above"
        );

        let strings =
            |items: &[&str]| -> Vec<String> { items.iter().map(|item| item.to_string()).collect() };
        assert_eq!(
            voice_connection_record_input(
                &UserVoiceChannel {
                    id: "CHAN".to_string(),
                    server_id: Some("SRV".to_string()),
                },
                "USER",
                "SID",
                "USER:DEV",
            ),
            VoiceConnectionRecordInput {
                keys: strings(&["vc_conns:CHAN", "vc_members:CHAN"]),
                args: strings(&["SID", "USER:DEV", "USER"]),
            }
        );

        // The one record builder feeds the one invocation.
        let body = flat_fn_body(&this_file_shipping(), "pub async fn record_voice_connection(");
        for needle in [
            "let input = voice_connection_record_input(channel, user_id, sid, identity);",
            "let mut invocation = RECORD_VOICE_CONNECTION.prepare_invoke();",
            "for key in &input.keys \u{7b} invocation.key(key); \u{7d}",
            "for arg in &input.args \u{7b} invocation.arg(arg); \u{7d}",
            "Ok(first) => Ok(first == 1),",
        ] {
            assert!(body.contains(needle), "`record_voice_connection` lost `{needle}`: {body}");
        }
    }

    /// S-3 D-1 + P2-4: `delete_voice_connection` peeks the record READ-ONLY,
    /// ends the watch session only when this sid is the user's last, and
    /// only then runs the script in connection mode; `Survivor` is the
    /// script's 2 and nothing else; the fallback is the degraded
    /// per-connection one, and every other error is returned.
    #[test]
    fn delete_voice_connection_peeks_then_runs_the_script() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn delete_voice_connection(");
        let at = |needle: &str| {
            body.find(needle).unwrap_or_else(|| {
                panic!("`delete_voice_connection` no longer has `{needle}`: {body}")
            })
        };

        let peek = at(".hgetall(voice_connections_key(channel))");
        let guard = at(
            "if another_connection_of(&recorded, user_id, sid).is_none() \u{7b} \
             watch::end_watch_session_if_host(channel, user_id).await; \u{7d}",
        );
        let input = at("let input = voice_connection_teardown_input(channel, user_id, sid);");
        let invoke = at("invocation.invoke_async::<_, i64>(&mut conn).await");
        assert!(peek < guard && guard < input && input < invoke, "{body}");
        assert_eq!(
            body.matches("end_watch_session_if_host(").count(),
            1,
            "the watch session ends in exactly one place, behind the peek: {body}"
        );
        for write in [".hdel(", ".hset(", ".del(", "Pipeline", ".query_async("] {
            assert!(
                !body[..invoke].contains(write),
                "`delete_voice_connection` writes `{write}` before the script: {body}"
            );
        }

        at("Ok(TEARDOWN_SURVIVOR) => Ok(ConnectionLeave::Survivor),");
        at("Ok(_) => Ok(ConnectionLeave::Last),");
        assert_eq!(super::TEARDOWN_SURVIVOR, 2);
        assert_eq!(body.matches("ConnectionLeave::Survivor").count(), 1, "{body}");
        let fallback = at("Err(error) if teardown_script_error_allows_fallback(&error) => ");
        assert!(
            body[fallback..].contains("\u{7d} delete_voice_connection_unconditionally(channel, user_id, sid).await \u{7d} Err(error) => "),
            "the per-connection fallback must run after the latch: {body}"
        );
        assert!(
            body.trim_end()
                .ends_with("Err(error).to_internal_error() \u{7d} \u{7d}"),
            "every other error is returned: {body}"
        );
        assert_eq!(
            call_sites(&shipping, "delete_voice_connection_unconditionally(").len(),
            1,
            "the degraded per-connection teardown is the script's fallback and nothing else"
        );

        // S-3 WA-6: a sid recorded as another user's is refused on the peek,
        // BEFORE the watch session can end, with an error and no write; the
        // script's own refusal maps to an error too, ahead of the fallback.
        let refuse = at(".filter(|identity| user_id_from_participant_identity(identity) != user_id);");
        assert!(peek < refuse && refuse < guard, "{body}");
        assert!(
            body[refuse..guard].contains("return Err(create_error!(InternalError));"),
            "{body}"
        );
        let script_refusal = at("Err(error) if teardown_refused_a_foreign_connection(&error) => ");
        assert!(script_refusal < fallback, "{body}");
        assert!(
            body[script_refusal..fallback].contains("Err(create_error!(InternalError))"),
            "{body}"
        );
    }

    /// S-3 WA-R: `delete_voice_connections` is `delete_voice_connection`'s
    /// shape in set mode: peek READ-ONLY, end the watch session only when no
    /// entry of the user would remain outside the set, then the script in
    /// `connections` mode, fed only by the pinned set input; a survivor is
    /// the script's 2 and nothing else; the degraded set fallback runs after
    /// the latch; every other error is returned.
    #[test]
    fn delete_voice_connections_peeks_then_runs_the_set_script() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn delete_voice_connections(");
        let at = |needle: &str| {
            body.find(needle).unwrap_or_else(|| {
                panic!("`delete_voice_connections` no longer has `{needle}`: {body}")
            })
        };

        let peek = at(".hgetall(voice_connections_key(channel))");
        let guard = at(
            "if another_connection_outside(&recorded, user_id, sids).is_none() \u{7b} \
             watch::end_watch_session_if_host(channel, user_id).await; \u{7d}",
        );
        let input = at("let input = voice_connections_teardown_input(channel, user_id, sids);");
        let invoke = at("invocation.invoke_async::<_, (i64, i64, i64)>(&mut conn).await");
        assert!(peek < guard && guard < input && input < invoke, "{body}");
        at("for key in &input.keys \u{7b} invocation.key(key); \u{7d}");
        at("for arg in &input.args \u{7b} invocation.arg(arg); \u{7d}");
        assert_eq!(body.matches("end_watch_session_if_host(").count(), 1, "{body}");
        for write in [".hdel(", ".hset(", ".del(", "Pipeline", ".query_async("] {
            assert!(
                !body.contains(write),
                "`delete_voice_connections` writes `{write}` outside the script: {body}"
            );
        }

        at("TEARDOWN_SURVIVOR => Ok(ConnectionLeave::Survivor),");
        at("_ => Ok(ConnectionLeave::Last),");
        assert_eq!(body.matches("ConnectionLeave::Survivor").count(), 1, "{body}");
        let fallback = at("Err(error) if teardown_script_error_allows_fallback(&error) => ");
        assert!(
            body[fallback..].contains(
                "\u{7d} delete_voice_connections_unconditionally(channel, user_id, sids).await \
                 \u{7d} Err(error) => "
            ),
            "the set fallback must run after the latch: {body}"
        );
        assert!(
            body.trim_end()
                .ends_with("Err(error).to_internal_error() \u{7d} \u{7d}"),
            "every other error is returned: {body}"
        );
        assert_eq!(
            call_sites(&shipping, "delete_voice_connections_unconditionally(").len(),
            1,
            "the degraded set teardown is the script's fallback and nothing else"
        );

        // The set fallback: this user's recorded sids only, then the same
        // survivor rule, then the unconditional teardown.
        let set_fallback =
            flat_fn_body(&shipping, "async fn delete_voice_connections_unconditionally(");
        assert!(
            set_fallback.contains(
                ".is_some_and(|identity| user_id_from_participant_identity(identity) == user_id)"
            ),
            "{set_fallback}"
        );
        assert!(
            set_fallback.ends_with(
                "delete_voice_state_unconditionally(channel, user_id).await?; \
                 Ok(ConnectionLeave::Last)"
            ),
            "{set_fallback}"
        );
    }

    /// S-3 D-4: `roster_connections` by value. Grouped by the OWNING user as
    /// `user_id_from_participant_identity` reads it — never by a string
    /// prefix, so `uu:B` is not `u`'s — and legs kept under their owner, in
    /// listed order. Mutation: grouping by `starts_with(user)` without the
    /// `:`.
    #[test]
    fn roster_connections_groups_by_owner_and_keeps_legs() {
        use super::roster_connections;

        let roster = roster_connections(
            ["u", "u:A", "uu:B", "u:A:screen", "v::screen", "v", "uu"]
                .map(str::to_string),
        );
        let strings =
            |items: &[&str]| -> Vec<String> { items.iter().map(|item| item.to_string()).collect() };

        assert_eq!(
            roster,
            [
                ("u".to_string(), strings(&["u", "u:A", "u:A:screen"])),
                ("uu".to_string(), strings(&["uu:B", "uu"])),
                ("v".to_string(), strings(&["v::screen", "v"])),
            ]
            .into_iter()
            .collect()
        );
        assert!(roster_connections(Vec::<String>::new()).is_empty());
    }

    /// B-2 + M-5 + L-6: `delete_voice_state` feeds the script ONLY from the
    /// pinned input, writes nothing to Redis outside the script, keeps the
    /// watch-session end first, and on a script error logs at ERROR and runs
    /// the unconditional fallback — which is the pre-script delete set.
    #[test]
    fn delete_voice_state_runs_the_script_and_falls_back_on_error() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "pub async fn delete_voice_state(");
        let at = |needle: &str| {
            body.find(needle)
                .unwrap_or_else(|| panic!("`delete_voice_state` no longer has `{needle}`: {body}"))
        };

        at("let input = voice_state_teardown_input(channel, user_id);");
        at("let mut invocation = DELETE_VOICE_STATE.prepare_invoke();");
        at("for key in &input.keys \u{7b} invocation.key(key); \u{7d}");
        at("for arg in &input.args \u{7b} invocation.arg(arg); \u{7d}");
        assert_eq!(body.matches(".key(").count(), 1, "one `.key(` only: {body}");
        assert_eq!(body.matches(".arg(").count(), 1, "one `.arg(` only: {body}");

        // L-6: every delete happens inside the one script.
        for write in ["Pipeline", ".srem(", ".hdel(", ".del(", ".query_async("] {
            assert!(
                !body.contains(write),
                "`delete_voice_state` writes `{write}` outside the script — a \
                 second round trip is a window for a re-join to be deleted"
            );
        }

        let invoke = at("invocation.invoke_async::<_, i64>(&mut conn).await");
        assert!(
            at("watch::end_watch_session_if_host(channel, user_id).await;") < invoke,
            "the watch session must still end BEFORE the state is deleted"
        );

        // M-5, narrowed by NEW-4: only an error the classifier accepts falls
        // back, and that arm falls back unconditionally — the latch inside it
        // picks the log level and nothing else.
        let fallback_arm_at = invoke
            + body[invoke..]
                .find("Err(error) if teardown_script_error_allows_fallback(&error) => ")
                .expect("a guarded fallback arm");
        let open = fallback_arm_at
            + body[fallback_arm_at..]
                .find('\u{7b}')
                .expect("a braced arm");
        let fallback_arm = braced_body(&body, open).trim();
        assert!(
            fallback_arm.starts_with(
                "if TEARDOWN_FALLBACK_LOGGED.swap(true, Ordering::Relaxed) \u{7b} log::debug!("
            ),
            "the fallback must open with the log-once latch, DEBUG once latched: \
             {fallback_arm}"
        );
        assert!(
            fallback_arm.contains("\u{7d} else \u{7b} log::error!("),
            "the first fallback in a process must be logged at ERROR: {fallback_arm}"
        );
        assert!(
            fallback_arm
                .ends_with("\u{7d} delete_voice_state_unconditionally(channel, user_id).await"),
            "the fallback must run AFTER the latch's if/else, outside both \
             branches, and return what it returns — the latch changes logging, \
             never whether the fallback runs: {fallback_arm}"
        );
        assert!(
            !fallback_arm.contains("return"),
            "nothing in the fallback arm may return before the fallback runs: \
             {fallback_arm}"
        );
        assert!(
            shipping
                .contains("static TEARDOWN_FALLBACK_LOGGED: AtomicBool = AtomicBool::new(false);"),
            "the log-once latch is gone"
        );

        // NEW-4: every other error is RETURNED, with no fallback and no retry.
        let other_arm_at = open
            + body[open..]
                .find("Err(error) => ")
                .expect("an unguarded Err arm");
        let open = other_arm_at + body[other_arm_at..].find('\u{7b}').expect("a braced arm");
        let other_arm = braced_body(&body, open).trim();
        assert!(
            other_arm.ends_with("Err(error).to_internal_error()"),
            "an error the classifier rejects must be returned: {other_arm}"
        );
        for banned in [
            "delete_voice_state_unconditionally(",
            "invoke_async",
            "DELETE_VOICE_STATE",
        ] {
            assert!(
                !other_arm.contains(banned),
                "an error the classifier rejects must not fall back or retry \
                 (`{banned}`): {other_arm}"
            );
        }
        // S-3 D-1: TWO call sites, and both are fallbacks of the same
        // script — this arm, and the per-connection fallback when the leaving
        // connection turns out to be the user's last. S-3 WA-R adds the THIRD,
        // the set-mode fallback in the same position (pinned in
        // `delete_voice_connections_peeks_then_runs_the_set_script`). Each is
        // pinned where it sits.
        assert_eq!(
            call_sites(&shipping, "delete_voice_state_unconditionally(").len(),
            3,
            "the unconditional teardown is the script's fallback and nothing \
             else: it wipes a newer channel's per-server state after a move"
        );
        let per_connection_fallback =
            flat_fn_body(&shipping, "async fn delete_voice_connection_unconditionally(");
        assert!(
            per_connection_fallback.ends_with(
                "delete_voice_state_unconditionally(channel, user_id).await?; \
                 Ok(ConnectionLeave::Last)"
            ),
            "the per-connection fallback reaches the unconditional teardown only \
             once no survivor is recorded: {per_connection_fallback}"
        );

        // The fallback is the pre-script delete set, every key unconditional,
        // after this user's entries leave the connection record (S-3 D-1).
        let fallback = flat_fn_body(&shipping, "async fn delete_voice_state_unconditionally(");
        let record_hdel = fallback
            .find("conn.hdel::<_, _, ()>(voice_connections_key(channel), theirs)")
            .unwrap_or_else(|| {
                panic!("the fallback no longer clears this user's connections: {fallback}")
            });
        assert!(
            fallback.contains(
                ".filter(|(_, identity)| user_id_from_participant_identity(identity) == user_id)"
            ),
            "the fallback must clear THIS user's connections only: {fallback}"
        );
        assert!(
            record_hdel < fallback.find("Pipeline::new()").expect("the pipeline"),
            "the connection record is cleared FIRST: {fallback}"
        );
        for needle in [
            "Pipeline::new()",
            ".srem(format!(\"vc_members:{}\", &channel.id), user_id)",
            ".srem(format!(\"vc:{user_id}\"), channel)",
            ".hdel(format!(\"vc_leg:{}\", &channel.id), user_id)",
            ".hdel(format!(\"voice_identity:{}\", &channel.id), user_id)",
            ".del(&[ format!(\"joined_at:{unique_key}\"), \
             format!(\"is_publishing:{unique_key}\"), \
             format!(\"is_receiving:{unique_key}\"), \
             format!(\"screensharing:{unique_key}\"), \
             format!(\"camera:{unique_key}\"), \
             format!(\"screen_video:{unique_key}\"), \
             format!(\"recording:{unique_key}\"), \
             format!(\"rc_capable:{unique_key}\"), \
             format!(\"watching:{unique_key}\"), \
             format!(\"annotations_allow:{}:{}\", &channel.id, user_id), \
             unique_key.clone(), ])",
        ] {
            assert!(
                fallback.contains(needle),
                "the fallback no longer issues `{needle}`: {fallback}"
            );
        }
    }

    /// NEW-4: which script failures may fall back to the unconditional
    /// teardown. Only a server reply proving the script never ran; above all
    /// NOT a transport error, after which the script may have run, kept a
    /// moved user's destination state, and lost its reply.
    ///
    /// Each class is built twice where it can be: from the `(ErrorKind, desc,
    /// detail)` constructors, and from WIRE BYTES through redis-rs's own
    /// parser, so the classifier is held to the errors the connection
    /// actually produces rather than to this test's idea of them.
    #[test]
    fn teardown_script_falls_back_only_when_the_script_provably_never_ran() {
        use super::teardown_script_error_allows_fallback as allows;
        use redis_kiss::redis::{parse_redis_value, ErrorKind, RedisError};
        use std::io;

        const SERVER: &str = "An error was signalled by the server";
        let server =
            |kind: ErrorKind, detail: &str| RedisError::from((kind, SERVER, detail.to_string()));
        let wire = |reply: &str| parse_redis_value(reply.as_bytes()).expect_err("an error reply");
        let io = |kind: io::ErrorKind| RedisError::from(io::Error::from(kind));

        // The script never ran: fall back.
        for (case, error) in [
            (
                "EVALSHA renamed away",
                server(
                    ErrorKind::ResponseError,
                    "unknown command 'EVALSHA', with args beginning with: 'abc' ",
                ),
            ),
            (
                "EVALSHA renamed away, off the wire",
                wire("-ERR unknown command `EVALSHA`, with args beginning with: \r\n"),
            ),
            (
                "NOSCRIPT after the reload",
                server(
                    ErrorKind::NoScriptError,
                    "No matching script. Please use EVAL.",
                ),
            ),
            (
                "NOSCRIPT, off the wire",
                wire("-NOSCRIPT No matching script. Please use EVAL.\r\n"),
            ),
            (
                "CROSSSLOT",
                server(
                    ErrorKind::CrossSlot,
                    "Keys in request don't hash to the same slot",
                ),
            ),
            (
                "CROSSSLOT, off the wire",
                wire("-CROSSSLOT Keys in request don't hash to the same slot\r\n"),
            ),
            (
                "an ACL refusing EVALSHA",
                wire("-NOPERM User default has no permissions to run the 'evalsha' command\r\n"),
            ),
            (
                "an ACL refusing SCRIPT LOAD",
                wire(
                    "-NOPERM User default has no permissions to run the 'script|load' command\r\n",
                ),
            ),
            // R3-3. The wording of every case marked "Redis 6 / KeyDB" (two
            // here, two in the returned set) is INFERRED from upstream Redis
            // 6.x source, not observed on a live server.
            (
                "an ACL refusing EVALSHA (Redis 6 / KeyDB wording)",
                wire(
                    "-NOPERM this user has no permissions to run the 'evalsha' command or its \
                     subcommand\r\n",
                ),
            ),
            (
                "an ACL refusing SCRIPT (Redis 6 / KeyDB wording)",
                wire(
                    "-NOPERM this user has no permissions to run the 'script' command or its \
                     subcommand\r\n",
                ),
            ),
        ] {
            assert!(allows(&error), "{case} must fall back: {error}");
        }

        // A garbled reply is `ResponseError` too — the reason the classifier
        // reads the detail rather than trusting the kind.
        let garbled = parse_redis_value(b"?not a reply\r\n").expect_err("a parse error");
        assert_eq!(garbled.kind(), ErrorKind::ResponseError, "{garbled}");

        // The script may have run, or did: returned, never a fallback.
        for (case, error) in [
            // R3-3, wording INFERRED from Redis 6.x source (see above): an ACL
            // key denial, and an ACL denial raised by a command the running
            // script called. Neither names EVALSHA or SCRIPT. The key denial
            // is checked before EVALSHA runs, so it is not returned because
            // the script ran: it is returned because the fallback touches the
            // same keys and would be refused too. First in the list so a
            // classifier broadened to match on "no permissions" alone is
            // reported against the case that exposes it.
            (
                "an ACL key denial (Redis 6 / KeyDB wording)",
                wire(
                    "-NOPERM this user has no permissions to access one of the keys used as \
                     arguments\r\n",
                ),
            ),
            (
                "an ACL denial inside the script (Redis 6 / KeyDB wording)",
                wire(
                    "-ERR Error running script (call to f_abc): @user_script:1: \
                     @user_script: 1: The user executing the script can't run this command \
                     or subcommand\r\n",
                ),
            ),
            ("a connection reset", io(io::ErrorKind::ConnectionReset)),
            ("a broken pipe", io(io::ErrorKind::BrokenPipe)),
            ("EOF mid-reply", io(io::ErrorKind::UnexpectedEof)),
            ("a timeout", io(io::ErrorKind::TimedOut)),
            ("a refused connection", io(io::ErrorKind::ConnectionRefused)),
            (
                "an IoError kind",
                RedisError::from((ErrorKind::IoError, "io")),
            ),
            ("a garbled reply", garbled),
            (
                "a reply that is not an integer",
                RedisError::from((
                    ErrorKind::TypeError,
                    "Response was of incompatible type",
                    "Response type not integer compatible.".to_string(),
                )),
            ),
            (
                "a Lua runtime error (Redis 6)",
                wire("-ERR Error running script (call to f_abc): @user_script:1: WRONGTYPE\r\n"),
            ),
            (
                "a Lua runtime error (Redis 7)",
                wire("-WRONGTYPE Operation against a key script: abc, on @user_script:1.\r\n"),
            ),
            (
                "a NOPERM from inside the script",
                wire("-NOPERM User default has no permissions to run the 'del' command\r\n"),
            ),
            ("a bare ERR", wire("-ERR\r\n")),
            (
                "LOADING",
                wire("-LOADING Redis is loading the dataset in memory\r\n"),
            ),
            ("BUSY", wire("-BUSY Redis is busy running a script.\r\n")),
            (
                "READONLY",
                wire("-READONLY You can't write against a read only replica.\r\n"),
            ),
            ("MOVED", wire("-MOVED 3999 127.0.0.1:6381\r\n")),
        ] {
            assert!(
                !allows(&error),
                "{case} must be returned, not fall back: {error}"
            );
        }
    }

    /// STRUCTURAL pin, standing in for a test that cannot run here: every
    /// voice-state teardown path clears `voice_identity:` — the script, the
    /// script's fallback, and the whole-call teardown.
    ///
    /// The behavioral version of this needs Redis, and the Redis-backed tests
    /// in this crate are the ones that fail on a build box with no server. So
    /// what is pinned instead is the shape.
    ///
    /// It matters because the mapping used to be cleared only by the callers
    /// that happened to remember: voice-ingress `participant_left` and the
    /// reconcile sweep call `delete_voice_participant_identity` on the line
    /// after `delete_voice_state`, and every other caller — `voice_join`'s
    /// `force_disconnect` loop above all — did not. The mapping left standing
    /// there is one of the two independent sources of the stale identities
    /// that made a voice move evict the wrong connection.
    ///
    /// Each path has its own needle, and each is proven red by its own
    /// mutation: dropping the script's HDEL line, and dropping the fallback's
    /// `.hdel`, each fail here on their own.
    ///
    /// The fallback needles are the KEY CONSTRUCTION, not the key name, and
    /// comment lines are skipped — both because the first draft of this test
    /// searched the body for the bare string `voice_identity:` and its
    /// known-bad control stayed GREEN: the prose explaining why the clear is
    /// there mentions the key, so deleting the clear left the assertion
    /// satisfied by a comment about the clear. A scan that its own mutation
    /// cannot turn red is decoration.
    #[test]
    fn both_voice_state_teardowns_clear_the_identity_mapping() {
        use super::{voice_state_teardown_input, UserVoiceChannel, DELETE_VOICE_STATE_LUA};

        // The script path: KEYS[5] is this channel's mapping, ARGV[2] the
        // user's field in it, and the script HDELs exactly that.
        let input = voice_state_teardown_input(
            &UserVoiceChannel {
                id: "CHAN".to_string(),
                server_id: Some("SRV".to_string()),
            },
            "USER",
        );
        assert_eq!(input.keys[4], "voice_identity:CHAN", "KEYS[5]");
        assert_eq!(input.args[1], "USER", "ARGV[2]");
        assert!(
            DELETE_VOICE_STATE_LUA
                .lines()
                .any(|line| line.trim() == "redis.call('HDEL', KEYS[5], ARGV[2])"),
            "the teardown script no longer clears the identity mapping"
        );

        let shipping = this_file_shipping();
        assert!(
            flat_fn_body(&shipping, "pub async fn delete_voice_state(")
                .contains("voice_state_teardown_input(channel, user_id)"),
            "`delete_voice_state` no longer runs the script with the input above"
        );

        // The fallback and the whole-call teardown, per-teardown, because
        // they clear it with different commands: one member leaving is an
        // HDEL of their field, a whole call ending is a DEL of the hash.
        const TEARDOWNS: [(&str, &str); 2] = [
            (
                "async fn delete_voice_state_unconditionally(",
                ".hdel(format!(\"voice_identity:",
            ),
            (
                "pub async fn delete_channel_voice_state(",
                ".del(format!(\"voice_identity:",
            ),
        ];

        for (teardown, command) in TEARDOWNS {
            let definition = shipping
                .find(teardown)
                .unwrap_or_else(|| panic!("mod.rs no longer defines `{teardown}`"));

            // The opening brace is written as an escape for the same reason
            // every other scan in this module writes its one that way:
            // `strip_test_items` used to count braces inside string literals
            // too, and a lone one here over-stripped the file. It reads them
            // off `blanked` text now (merge slice S6RM-5); the escape stays.
            let open = definition
                + shipping[definition..]
                    .find('\u{7b}')
                    .expect("the teardown has a body");

            let cleared = braced_body(&shipping, open).lines().any(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && trimmed.contains(command)
            });

            assert!(
                cleared,
                "`{teardown}` no longer issues `{command}`. It is the \
                 chokepoint the leave / reconcile / force-disconnect paths \
                 share, and a mapping that outlives the voice state it \
                 described is a stale identity that moderation and the voice \
                 move will resolve to and act on"
            );
        }
    }

    /// The leg identity grammar (android-screen-share plan §2.2 / §0-R.3).
    /// Three segments ALWAYS: `"{primary}:screen"` on a bare primary yields
    /// the two-segment `user:screen`, which every existing parser reads as
    /// device = "screen" — `member_edit`'s `strip_prefix("{user}:")` included.
    #[test]
    fn screen_leg_identity_always_has_three_segments() {
        use super::{is_screen_leg, participant_leg, screen_leg_identity};

        let user = "01KX7HASD9FHBYA3XGKA5YACYX";
        let device = "4208aa7e9ff58761b2d7a5d6c45f7383";
        let qualified = format!("{user}:{device}");

        let leg = screen_leg_identity(&qualified);
        assert_eq!(leg, format!("{user}:{device}:screen"));

        let bare_leg = screen_leg_identity(user);
        assert_eq!(bare_leg, format!("{user}::screen"));
        assert_eq!(bare_leg.split(':').count(), 3);
        assert_eq!(
            bare_leg.split(':').nth(1),
            Some(""),
            "a bare primary gets an EMPTY device segment, not a device named \"screen\""
        );

        for identity in [&leg, &bare_leg] {
            assert!(is_screen_leg(identity));
            assert_eq!(participant_leg(identity), Some("screen"));
            // Every existing parser takes segment 0 (user) or 1 (device) and
            // survives a third — the property the whole design rests on.
            assert_eq!(user_id_from_participant_identity(identity), user);
        }

        // One- and two-segment identities are PRIMARIES, never legs.
        assert_eq!(participant_leg(user), None);
        assert!(!is_screen_leg(user));
        assert_eq!(participant_leg(&qualified), None);
        assert!(!is_screen_leg(&qualified));

        // A fourth segment lands INSIDE the third (splitn stops at three), so
        // `user:dev:screen:anything` is not a leg.
        let overlong = format!("{user}:{device}:screen:extra");
        assert_eq!(participant_leg(&overlong), Some("screen:extra"));
        assert!(!is_screen_leg(&overlong));
    }

    #[test]
    fn remote_control_permissions_flip_exactly_one_field() {
        use super::remote_control_participant_permissions;

        // Media-E2EE plan §0.4 amendment, test 2 (subsumes slice 1's
        // `remote_control_grant_carries_full_set_and_flips_only_data`).
        // UpdateParticipantOptions replaces the WHOLE ParticipantPermission
        // message: the grant path must differ from the sync path in exactly
        // one field, or the controller goes mute/deaf on grant. Full
        // cross-product of can_listen x every subset of the publishable
        // sources; the struct-update comparison covers every field,
        // including ones ParticipantPermission grows later.
        let all_sources = [
            TrackSource::Microphone,
            TrackSource::Camera,
            TrackSource::ScreenShare,
            TrackSource::ScreenShareAudio,
        ];
        for can_listen in [false, true] {
            for mask in 0u8..1 << all_sources.len() {
                let sources: Vec<TrackSource> = all_sources
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & 1 << bit != 0)
                    .map(|(_, source)| *source)
                    .collect();

                let granted = remote_control_participant_permissions(can_listen, &sources);
                let baseline = voice_participant_permissions(can_listen, &sources);

                assert!(granted.can_publish_data);
                assert_eq!(
                    livekit_protocol::ParticipantPermission {
                        can_publish_data: false,
                        ..granted
                    },
                    baseline,
                    "the grant may differ from the sync baseline ONLY in can_publish_data \
                     (can_listen={can_listen}, sources={sources:?})"
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
                        not_afk(),
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

    // ---- source-contract tests (media-E2EE plan §0.4 amendment, 3 & 4) ----
    //
    // What bounds the data-publish surface is not a runtime property but the
    // SHAPE of the code: how many call sites can mint the remote-control
    // permission set, and what every other SFU permission push carries. The
    // desktop shell's `assert_remote_control_injection_contract`
    // (src-tauri/build.rs) is the house precedent for holding a shape like
    // that in CI; these two tests do the same for the backend workspace.

    /// The workspace `crates/` directory, resolved from this crate's
    /// manifest so the scan works from any test runner cwd.
    fn workspace_crates_dir() -> std::path::PathBuf {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .expect("workspace root above crates/core/database")
            .join("crates");
        // Fail loudly if the layout moves — a scan over nothing asserts
        // nothing.
        assert!(
            dir.join("delta").is_dir(),
            "{} does not look like the workspace crates directory",
            dir.display()
        );
        dir
    }

    fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read workspace directory") {
            let path = entry.expect("read workspace directory entry").path();
            if path.is_dir() {
                // target/ holds build products, never our sources
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// `source` with every comment blanked and, with `literals`, every string
    /// and char literal too: each of their bytes becomes a space, and
    /// newlines stay. Byte offsets and lines are unchanged, so a position
    /// found in the result is the same position in `source`.
    ///
    /// The scans here match needles textually. With comments blanked, a
    /// trailing `// ...` can neither satisfy a needle nor trip a ban (merge
    /// slice S6B-4, S6R-4: only whole-line comments used to be dropped); with
    /// literals blanked too, a brace inside a string or char literal does not
    /// move a brace depth (S6F3A-2) and a `#[cfg(test)]` in a string is no
    /// attribute (S6RM-5).
    /// Lexed as delta's `util::test::without_comments` lexes: `//` to the end
    /// of the line (doc comments too), nested `/* */`, strings and byte
    /// strings with their escapes, raw strings (`r"..."`, `r#"..."#`), and
    /// char literals (`'"'`, `'\''`, longer escapes), told from a lifetime
    /// by their closing quote. An unclosed comment or literal panics, naming
    /// `rel`: a lexer that ran off the end would blank the rest of the file.
    /// Raw byte and raw C strings (`br"..."`, `cr#"..."#`) are raw strings
    /// too (HD re-audit HDA-8): read as plain strings, a backslash or quote
    /// inside one would put the lexer out of phase.
    fn blanked(rel: &str, source: &str, literals: bool) -> String {
        fn is_ident(ch: char) -> bool {
            ch.is_alphanumeric() || ch == '_'
        }

        fn unclosed(rel: &str, what: &str) -> ! {
            panic!("an unclosed {what} in {rel}")
        }

        let chars: Vec<char> = source.chars().collect();
        let char_at = |at: usize| chars.get(at).copied();
        let mut blank = vec![false; chars.len()];
        let mut at = 0;
        while let Some(ch) = char_at(at) {
            let start = at;
            let literal = match (ch, char_at(at + 1)) {
                ('/', Some('/')) => {
                    while char_at(at).is_some_and(|ch| ch != '\n') {
                        at += 1;
                    }
                    false
                }
                ('/', Some('*')) => {
                    let mut depth = 0usize;
                    loop {
                        match (char_at(at), char_at(at + 1)) {
                            (Some('/'), Some('*')) => {
                                depth += 1;
                                at += 2;
                            }
                            (Some('*'), Some('/')) => {
                                depth -= 1;
                                at += 2;
                                if depth == 0 {
                                    break;
                                }
                            }
                            (Some(_), _) => at += 1,
                            (None, _) => unclosed(rel, "/* comment"),
                        }
                    }
                    false
                }
                ('"', _) => {
                    at += 1;
                    loop {
                        match char_at(at) {
                            Some('\\') => at += 2,
                            Some('"') => {
                                at += 1;
                                break;
                            }
                            Some(_) => at += 1,
                            None => unclosed(rel, "string literal"),
                        }
                    }
                    true
                }
                ('r', _)
                    if at == 0
                        || !is_ident(chars[at - 1])
                        || (matches!(chars[at - 1], 'b' | 'c')
                            && (at == 1 || !is_ident(chars[at - 2]))) =>
                {
                    let mut quote = at + 1;
                    while char_at(quote) == Some('#') {
                        quote += 1;
                    }
                    if char_at(quote) != Some('"') {
                        // `r` starting an identifier, or a raw identifier `r#name`
                        at += 1;
                        continue;
                    }
                    // The closing quote, followed by as many `#` as opened it
                    let hashes = quote - at - 1;
                    let mut close = quote + 1;
                    loop {
                        match char_at(close) {
                            Some('"')
                                if (1..=hashes)
                                    .all(|offset| char_at(close + offset) == Some('#')) =>
                            {
                                break
                            }
                            Some(_) => close += 1,
                            None => unclosed(rel, "raw string literal"),
                        }
                    }
                    at = close + hashes + 1;
                    true
                }
                ('\'', Some('\\')) => {
                    // An escaped char literal: `'\''`, `'\\'` and longer escapes
                    let close = (at + 3..chars.len())
                        .find(|&close| chars[close] == '\'')
                        .unwrap_or_else(|| unclosed(rel, "char literal"));
                    at = close + 1;
                    true
                }
                ('\'', Some(_)) if char_at(at + 2) == Some('\'') => {
                    // A plain char literal, `'"'` included
                    at += 3;
                    true
                }
                _ => {
                    // Everything else, a lifetime's `'` included
                    at += 1;
                    continue;
                }
            };
            if literals || !literal {
                blank[start..at.min(chars.len())].fill(true);
            }
        }

        let mut out = String::with_capacity(source.len());
        for (ch, blank) in chars.iter().zip(blank) {
            if blank && *ch != '\n' {
                out.extend(std::iter::repeat(' ').take(ch.len_utf8()));
            } else {
                out.push(*ch);
            }
        }
        out
    }

    /// `blanked` on a synthetic source: every comment and (with `literals`)
    /// every literal is blanked, code is kept, and every byte offset and
    /// line survives, so a position found in the result indexes the source.
    #[test]
    fn blanked_blanks_comments_and_literals_in_place() {
        let source = concat!(
            "keep(1); // gone(1) trailing \u{2014} with a multi-byte char\n",
            "/// gone(2);\n",
            "keep(2); /* gone(3); */ keep(3);\n",
            "/*\ngone(4);\n*/ keep(4);\n",
            "/* outer /* gone(5); */ gone(6); */ keep(5);\n",
            "let url = \"http://127.0.0.1:1 \u{7d}\"; keep(6);\n",
            "let raw = r#\"a // \"quoted\" /* \u{7b} b\"#; keep(7);\n",
            "let bytes = br\"c // d\"; let byte = b'\u{7b}'; keep(8);\n",
            "let escaped = \"e \\\" // f\"; keep(9);\n",
            "let quote = '\"'; let tick = '\\''; let brace = '\\u{7d}'; keep(10);\n",
            "fn f<'a>(x: &'a str) -> &'a str \u{7b} x \u{7d} // gone(7);\n",
            "let r#type = 1; keep(11); // gone(8);\n",
        );

        for literals in [false, true] {
            let code = blanked("test", source, literals);
            assert_eq!(code.len(), source.len(), "byte offsets survive");
            assert_eq!(
                code.lines().count(),
                source.lines().count(),
                "lines survive"
            );
            for (kept, original) in code.lines().zip(source.lines()) {
                assert_eq!(kept.len(), original.len(), "`{original}` keeps its width");
            }
            assert!(!code.contains("gone("), "{code}");
            for n in 1..=11 {
                let needle = format!("keep({n})");
                assert_eq!(
                    code.find(&needle),
                    source.find(&needle),
                    "`{needle}` stays where it was: {code}"
                );
            }
            assert!(code.contains("fn f<'a>(x: &'a str) -> &'a str \u{7b} x \u{7d}"));
            assert!(code.contains("let r#type = 1;"));
        }

        let comments_only = blanked("test", source, false);
        for literal in [
            "\"http://127.0.0.1:1 \u{7d}\"",
            "r#\"a // \"quoted\" /* \u{7b} b\"#",
            "br\"c // d\"",
            "b'\u{7b}'",
            "\"e \\\" // f\"",
            "'\"'",
            "'\\''",
            "'\\u{7d}'",
        ] {
            assert!(
                comments_only.contains(literal),
                "`{literal}` lost: {comments_only}"
            );
        }

        let code = blanked("test", source, true);
        for literal in ["http", "quoted", "c // d", "e \\\"", "'\"'", "'\\''"] {
            assert!(!code.contains(literal), "`{literal}` kept: {code}");
        }
        let braces = |text: &str| text.matches(['\u{7b}', '\u{7d}']).count();
        assert_eq!(
            braces(&code),
            2,
            "only the fn body's braces are code: {code}"
        );

        for unclosed in ["a /* b", "a \"b", "a r#\"b\"", "a '\\u{7b}"] {
            assert!(
                std::panic::catch_unwind(|| blanked("test", unclosed, true)).is_err(),
                "`{unclosed}` must not run off the end silently"
            );
        }
    }

    /// HD re-audit HDA-8: a raw C string is a raw string. Read as a plain
    /// string, `cr"C:\"` would escape its own closing quote and run on
    /// through the code after it, and `cr#"a "b" c"#` would end at its first
    /// inner quote. Control: `c` dropped from the raw prefixes (this goes
    /// red).
    #[test]
    fn blanked_reads_raw_c_strings_as_raw() {
        let source = concat!(
            "let path = cr\"C:\\\"; keep(1); // gone(1)\n",
            "let hashed = cr#\"a \"b // c\" \u{7b}\"#; keep(2); // gone(2)\n",
            "let cr = 1; let plain = c\"d // e\"; keep(3); // gone(3)\n",
        );
        for literals in [false, true] {
            let code = blanked("test", source, literals);
            assert_eq!(code.len(), source.len(), "byte offsets survive");
            assert!(!code.contains("gone("), "{code}");
            for n in 1..=3 {
                let needle = format!("keep({n})");
                assert_eq!(code.find(&needle), source.find(&needle), "{code}");
            }
            assert!(code.contains("let cr = 1;"), "{code}");
        }

        let comments_only = blanked("test", source, false);
        for literal in ["cr\"C:\\\"", "cr#\"a \"b // c\" \u{7b}\"#", "c\"d // e\""] {
            assert!(
                comments_only.contains(literal),
                "`{literal}` lost: {comments_only}"
            );
        }
        let code = blanked("test", source, true);
        for literal in ["C:", "b // c", "d // e", "\u{7b}"] {
            assert!(!code.contains(literal), "`{literal}` kept: {code}");
        }
    }

    /// Remove every `#[cfg(test)]`-gated item from `source` so the scans
    /// below see only code that ships. Matching is TEXTUAL: the attribute,
    /// then either a brace-matched body or a bodyless item ending in `;`
    /// (trait method declarations). Getting it wrong cannot pass silently:
    /// both scans below assert their known call sites are FOUND, so an
    /// over-strip that eats shipping code fails the run.
    ///
    /// Merge slice S6RM-5: both the attribute and the braces are read off
    /// [`blanked`] text (comments AND literals blanked, offsets kept). So
    /// `#[cfg(test)]` counts only as an attribute, outside comments and
    /// string literals: a comment that mentions it no longer strips the
    /// shipping item below it. And a brace in a test string or comment no
    /// longer moves the match. (The `\u{7b}` escapes in this module's test
    /// strings predate that; they stay harmless.)
    ///
    /// HD re-audit HDA-4: on that text an `#[cfg(test)]` can only be a real
    /// attribute, so it is honored wherever an item can start: at the start
    /// of its line, or right after (whitespace aside) a `]` (another
    /// attribute), a `}`, a `;` or a `{`. Anywhere else (a parameter or a
    /// field of a one-line list, after `(` or `,`) it panics, naming the
    /// file: keeping it as shipping would let test-only code stand in for
    /// shipping code in every presence and count pin, and guessing its extent
    /// could strip shipping code. rustfmt never writes either shape.
    ///
    /// Audit LOW-2 (wave-3 completion audit): an item whose braces never
    /// balance used to run silently to EOF, which SILENTLY DELETES every
    /// shipping line below it — in this file, the entire second half. A
    /// scanner that truncates on malformed input is a false-PASS generator,
    /// so it now panics instead, naming the file and what to do about it.
    fn strip_test_items(rel: &str, source: &str) -> String {
        const ATTR: &str = "#[cfg(test)]";
        let code = blanked(rel, source, true);
        let mut shipping = String::with_capacity(source.len());
        let mut kept_from = 0;
        let mut search_from = 0;
        while let Some(found) = code[search_from..].find(ATTR) {
            let attr = search_from + found;
            let line_start = code[..attr].rfind('\n').map_or(0, |nl| nl + 1);
            let before = code[line_start..attr].trim_end();
            assert!(
                before.is_empty() || before.ends_with([']', '}', ';', '{']),
                "a `{ATTR}` in {rel} follows `{before}` on its line, where no item \
                 starts: this scan cannot tell what it gates"
            );
            shipping.push_str(&source[kept_from..attr]);
            let after = attr + ATTR.len();

            let mut depth = 0i64;
            let mut item_end = None;
            for (i, ch) in code[after..].char_indices() {
                match ch {
                    ';' if depth == 0 => {
                        item_end = Some(i + 1);
                        break;
                    }
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        assert!(depth >= 0, "unbalanced braces after {ATTR} in {rel}");
                        if depth == 0 {
                            item_end = Some(i + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let item_end = item_end.unwrap_or_else(|| {
                panic!(
                    "a `{ATTR}` item in {rel} is never closed — it ran to end \
                     of file: a brace outside every comment and literal is \
                     unbalanced. Truncating here would silently delete every \
                     shipping line below it from this scan"
                )
            });
            kept_from = after + item_end;
            search_from = kept_from;
        }
        shipping.push_str(&source[kept_from..]);
        shipping
    }

    /// `strip_test_items` on a synthetic source (merge slice S6RM-5): only a
    /// `#[cfg(test)]` outside comments and literals strips an item, and a
    /// brace in a literal inside the stripped item does not end it early.
    ///
    /// HD re-audit HDA-4: an attribute in the middle of a line, where an item
    /// can start (after a `}`, a `;`, a `{` or another attribute), strips its
    /// item like one at the start of the line (`mid_line` used to be kept as
    /// shipping), and one anywhere else fails the scan. Control: the old
    /// start-of-line rule (`mid_line` and the other mid-line items are kept,
    /// and nothing panics).
    #[test]
    fn strip_test_items_honours_only_a_real_attribute() {
        let source = [
            "pub fn kept_a() \u{7b} \u{7d}",
            "// a comment naming #[cfg(test)] strips nothing",
            "pub fn kept_b() \u{7b} \u{7d}",
            "/* #[cfg(test)] */ pub fn kept_c() \u{7b} \u{7d}",
            "const NOTE: &str = \"#[cfg(test)]\"; pub fn kept_d() \u{7b} \u{7d}",
            "pub fn kept_e() \u{7b} let _ = 1; \u{7d} #[cfg(test)] fn mid_line() \u{7b} \u{7d}",
            "    #[cfg(test)]",
            "    fn gone_a() \u{7b} let _ = \"\u{7d}\"; let _ = '\u{7d}'; // \u{7d}",
            "    \u{7d}",
            "#[cfg(test)]",
            "mod gone_b;",
            "pub fn kept_f() \u{7b} \u{7d}",
            "#[inline] #[cfg(test)] fn gone_c() \u{7b} \u{7d}",
            "pub const KEPT_G: u8 = 1; #[cfg(test)] const GONE_D: u8 = 2;",
            "pub mod kept_h \u{7b} #[cfg(test)] fn gone_e() \u{7b} \u{7d} \u{7d}",
        ]
        .join("\n");
        let shipping = strip_test_items("test", &source);
        for kept in [
            "kept_a", "kept_b", "kept_c", "kept_d", "kept_e", "kept_f", "KEPT_G", "kept_h",
        ] {
            assert!(shipping.contains(kept), "`{kept}` stripped: {shipping}");
        }
        for gone in ["gone_a", "gone_b", "mid_line", "gone_c", "GONE_D", "gone_e"] {
            assert!(!shipping.contains(gone), "`{gone}` kept: {shipping}");
        }

        for where_no_item_starts in [
            "pub fn f(#[cfg(test)] x: u8) \u{7b} \u{7d}",
            "const S: T = T \u{7b} a: 1, #[cfg(test)] b: 2 \u{7d};",
        ] {
            assert!(
                std::panic::catch_unwind(|| strip_test_items("test", where_no_item_starts))
                    .is_err(),
                "`{where_no_item_starts}` must fail the scan, not be kept as shipping"
            );
        }
    }

    /// Every shipping Rust source in the workspace, as (crates/-relative
    /// path, text with every `#[cfg(test)]` item stripped and every comment,
    /// trailing ones included, [`blanked`]). Byte offsets are those of the
    /// stripped text; string literals are kept, so needles that match inside
    /// them still do.
    fn shipping_sources() -> Vec<(String, String)> {
        let crates_dir = workspace_crates_dir();
        let mut files = Vec::new();
        rust_sources(&crates_dir, &mut files);
        assert!(
            files.len() > 300,
            "suspiciously small workspace scan ({} files) — asserting over nothing",
            files.len()
        );
        files
            .iter()
            .map(|path| {
                let text = std::fs::read_to_string(path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                let rel = path
                    .strip_prefix(&crates_dir)
                    .expect("scanned file outside crates/")
                    .to_string_lossy()
                    .replace('\\', "/");
                let shipping = blanked(&rel, &strip_test_items(&rel, &text), false);
                (rel, shipping)
            })
            .collect()
    }

    /// Byte offsets of call sites of `needle` (an identifier followed by
    /// `(`) in stripped source — the definition line, `use` imports, and
    /// comments are not callers. `shipping_sources` has blanked every
    /// comment, trailing ones included (merge slice S6B-4), so the whole-line
    /// check below is redundant on its text and kept as a second guard.
    ///
    /// Counted on [`blanked`] text with the literals blanked too (HD re-audit
    /// HDA-5): a string that holds the needle (a log line, say, left where
    /// a deleted call was) is no call, so it cannot stand in for one in a
    /// presence or count pin. The offsets are those of `shipping`, which
    /// keeps its literals for the needles that must match inside them.
    fn call_sites(shipping: &str, needle: &str) -> Vec<usize> {
        if !shipping.contains(needle) {
            return Vec::new();
        }
        let code = blanked("call_sites", shipping, true);
        code.match_indices(needle)
            .map(|(at, _)| at)
            .filter(|at| {
                let line_start = code[..*at].rfind('\n').map_or(0, |nl| nl + 1);
                let before_match = &code[line_start..*at];
                let trimmed = before_match.trim_start();
                // ends_with, not contains: only the definition itself is
                // exempt, never a call that happens to share a line with
                // `fn `
                !before_match.ends_with("fn ")
                    && !trimmed.starts_with("//")
                    && !trimmed.starts_with("use ")
            })
            .collect()
    }

    /// HD re-audit HDA-5: a needle inside a string or char literal is no call
    /// site, and the one real call is found where it stands. Control: the
    /// needle counted on the literal-keeping text (the literal counts too).
    #[test]
    fn call_sites_ignore_a_needle_inside_a_literal() {
        let shipping = [
            "fn f() \u{7b}",
            "    tracing::warn!(\"set_voice_participant_session(a, b) failed\");",
            "    let _ = r#\"set_voice_participant_session(\"#;",
            "    set_voice_participant_session(a, b);",
            "\u{7d}",
        ]
        .join("\n");
        let call = shipping
            .rfind("set_voice_participant_session(a, b);")
            .expect("the call");
        assert_eq!(
            call_sites(&shipping, "set_voice_participant_session("),
            vec![call]
        );
        assert!(call_sites(&shipping, "not_there(").is_empty());
    }

    /// The argument text of a call whose opening `(` sits at byte `open`,
    /// exclusive of the parentheses themselves. Paren-matching on the raw
    /// text (unlike `strip_test_items`, which reads `blanked` text): callers
    /// must keep parentheses BALANCED inside strings and comments in the code
    /// being scanned.
    fn call_args(shipping: &str, open: usize) -> &str {
        let mut depth = 0i64;
        for (i, ch) in shipping[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &shipping[open + 1..open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced parens in a call at byte {open}");
    }

    #[test]
    fn remote_control_permissions_have_exactly_one_caller() {
        // §0.4 amendment test 3 — the one that preserves the ORIGINAL
        // invariant's meaning. `permission_sync_never_regrants_data_publishing`
        // stood for "no participant in any room holds can_publish_data";
        // `remote_control_participant_permissions` reopens that per grant,
        // so the property is now carried by CARDINALITY: exactly one
        // non-test call site in the workspace may mint the RC set, and it
        // is `control_respond`, behind an accepted offer. The SFU grant is
        // per-IDENTITY with no per-topic scoping — a granted controller can
        // publish on ANY data topic, including "captions" — so this single
        // call site is what bounds that surface.
        const NEEDLE: &str = "remote_control_participant_permissions(";
        const CALLER_FILE: &str = "delta/src/routes/channels/remote_control.rs";

        let sources = shipping_sources();
        let callers: Vec<(&str, usize)> = sources
            .iter()
            .flat_map(|(rel, shipping)| {
                call_sites(shipping, NEEDLE)
                    .into_iter()
                    .map(move |at| (rel.as_str(), at))
            })
            .collect();

        assert_eq!(
            callers.iter().map(|(rel, _)| *rel).collect::<Vec<_>>(),
            vec![CALLER_FILE],
            "remote_control_participant_permissions must have exactly ONE \
             non-test caller in the workspace (control_respond, behind an \
             accepted offer). A second caller is a second code path that \
             grants data publishing — re-read media-E2EE plan §0.4 before \
             adding one"
        );

        // ... and that one caller sits inside control_respond's body.
        let (_, at) = callers[0];
        let shipping = &sources
            .iter()
            .find(|(rel, _)| rel == CALLER_FILE)
            .expect("the caller file was just found above")
            .1;
        let fn_start = shipping
            .find("fn control_respond")
            .expect("control_respond left the file — move this contract with it");
        let fn_end = fn_start
            + shipping[fn_start..]
                .find("\npub async fn ")
                .unwrap_or(shipping.len() - fn_start);
        assert!(
            (fn_start..fn_end).contains(&at),
            "the single remote_control_participant_permissions call site \
             moved out of control_respond — only an ACCEPTED offer may mint \
             the RC permission set"
        );
    }

    #[test]
    fn remote_control_teardown_restores_the_sync_permission_set() {
        // §0.4 amendment test 4: every SFU permission push in the
        // workspace carries the sync set (voice_participant_permissions) —
        // the grant in control_respond is the ONE sanctioned exception
        // (previous test). In particular every teardown path RESTORES the
        // sync set: pushing the RC variant on teardown would re-grant data
        // publishing at the exact moment the code believes it revoked it.
        // AFK Stage 6 F-A1 added the two classifying `_if_present` pushes;
        // each is a needle of its own because none of these is a prefix of
        // another once the `(` is included.
        //
        // S-3 D-4 (lane B1) added `update_permissions_connections`, and the
        // needles are now ALSO derived from the transport itself: every
        // `pub async fn update_permissions…` in its shipping code becomes a
        // needle, so a push method added there is scanned without anyone
        // remembering to list it here. The literal list stays for the push
        // methods that exist. The S-3 cleanup pruned the two whose method is
        // gone (`.update_permissions(`, deleted in S-3 RB-1, and
        // `.update_permissions_if_present(`, deleted in the cleanup): no
        // shipping line matched either any more, so they scanned nothing, and
        // a method of either name that comes back in the transport becomes a
        // needle through the derivation below anyway.
        const PUSHES: [&str; 3] = [
            ".update_permissions_identity(",
            ".update_permissions_identity_if_present(",
            ".update_permissions_connections(",
        ];
        const PUSH_METHOD: &str = "pub async fn update_permissions";
        const SYNC: &str = "voice_participant_permissions(";
        const GRANT: &str = "remote_control_participant_permissions(";
        // The typed transport: its `new_permissions` parameter is
        // caller-supplied, so it is the one file exempt from the
        // constructor-inline rule below.
        const TRANSPORT_FILE: &str = "core/database/src/voice/voice_client.rs";
        const GRANT_FILE: &str = "delta/src/routes/channels/remote_control.rs";

        let mut sync_pushes: Vec<&str> = Vec::new();
        let mut grant_pushes: Vec<&str> = Vec::new();
        let mut saw_transport = false;

        let sources = shipping_sources();

        let transport = &sources
            .iter()
            .find(|(rel, _)| rel == TRANSPORT_FILE)
            .expect("the transport file moved — update this contract's exclusion")
            .1;
        let derived: Vec<String> = transport
            .match_indices(PUSH_METHOD)
            .map(|(at, _)| {
                let name = &transport[at + "pub async fn ".len()..];
                let end = name
                    .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                    .expect("a method name ends");
                format!(".{}(", &name[..end])
            })
            .collect();
        assert!(
            derived
                .iter()
                .any(|needle| needle == ".update_permissions_connections("),
            "the derivation found no push method in {TRANSPORT_FILE}, so it scans nothing \
             of its own: {derived:?}"
        );
        let mut needles: Vec<String> = PUSHES.iter().map(|needle| needle.to_string()).collect();
        for needle in derived {
            if !needles.contains(&needle) {
                needles.push(needle);
            }
        }

        for (rel, shipping) in &sources {
            if rel == TRANSPORT_FILE {
                saw_transport = true;
                continue;
            }
            for needle in needles.iter().map(String::as_str) {
                for (at, _) in shipping.match_indices(needle) {
                    // The permission argument lives inside this call's
                    // parentheses; classify by which constructor appears
                    // there. Paren-matching on the raw text, like
                    // `call_args`.
                    let open = at + needle.len() - 1;
                    let mut depth = 0i64;
                    let mut close = None;
                    for (i, ch) in shipping[open..].char_indices() {
                        match ch {
                            '(' => depth += 1,
                            ')' => {
                                depth -= 1;
                                if depth == 0 {
                                    close = Some(open + i);
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    let args = &shipping
                        [open..close.expect("unbalanced parens in a permission push")];

                    match (args.contains(SYNC), args.contains(GRANT)) {
                        (true, false) => sync_pushes.push(rel.as_str()),
                        (false, true) => grant_pushes.push(rel.as_str()),
                        _ => panic!(
                            "unclassifiable SFU permission push in {rel} — pass \
                             voice_participant_permissions or (in control_respond \
                             only) remote_control_participant_permissions INLINE \
                             so this contract can see it"
                        ),
                    }
                }
            }
        }

        assert!(
            saw_transport,
            "{TRANSPORT_FILE} moved — update this contract's exclusion"
        );
        assert_eq!(
            grant_pushes,
            vec![GRANT_FILE],
            "exactly one SFU push may carry the RC permission set: the \
             accept in control_respond"
        );
        // The known restore paths must all be present and classified as
        // sync. This doubles as the loud-failure guard on strip_test_items:
        // the sync push in voice/mod.rs sits AFTER this very test module,
        // so an over-strip would make it vanish from the scan and fail
        // here.
        for expected in [
            "core/database/src/voice/mod.rs",            // permission-sync push
            "core/database/src/voice/remote_control.rs", // active revoke leg of teardown
            GRANT_FILE, // raced-teardown undo in control_respond
        ] {
            assert!(
                sync_pushes.contains(&expected),
                "expected a voice_participant_permissions push in {expected} — \
                 if the restore path moved, move this inventory with it"
            );
        }
    }

    /// Every shipping file of the workspace with its comment lines dropped
    /// and every run of whitespace collapsed to one space. With `squeeze`,
    /// whitespace is removed altogether, so a needle survives any rustfmt
    /// wrap (but `fn name(` then reads `fnname(`).
    fn flat_shipping_sources(squeeze: bool) -> Vec<(String, String)> {
        shipping_sources()
            .into_iter()
            .map(|(rel, shipping)| {
                let code = shipping
                    .lines()
                    .filter(|line| !line.trim_start().starts_with("//"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let flat = if squeeze {
                    code.chars().filter(|ch| !ch.is_whitespace()).collect()
                } else {
                    code.split_whitespace().collect::<Vec<_>>().join(" ")
                };
                (rel, flat)
            })
            .collect()
    }

    /// AFK S-3 D-5 (cleanup): no shipping file outside the transport calls a
    /// LiveKit room-client method. `RoomClient.client` is private, so the
    /// compiler refuses `.client.` outside `voice_client.rs`; this covers the
    /// other bypass, a file that builds or names its own
    /// `livekit_api::services::room::RoomClient`. Either way the call would
    /// run with no `SFU_CALL_TIMEOUT` and no breaker. The needles are the
    /// room service's methods whose names no `VoiceClient` method shares
    /// (`create_room` and `delete_room` are shared, so they are matched only
    /// on a raw `.client.`), plus any path to, or construction of, the
    /// LiveKit type itself.
    #[test]
    fn no_shipping_file_outside_the_transport_calls_the_room_client() {
        const TRANSPORT_FILE: &str = "core/database/src/voice/voice_client.rs";
        const ROOM_CLIENT: [&str; 16] = [
            ".remove_participant(",
            ".update_participant(",
            ".mute_published_track(",
            ".list_participants(",
            ".list_rooms(",
            ".get_participant(",
            ".update_room_metadata(",
            ".update_subscriptions(",
            ".send_data(",
            ".forward_participant(",
            ".move_participant(",
            ".client.create_room(",
            ".client.delete_room(",
            "services::room",
            "room::RoomClient",
            "RoomClient::",
        ];

        let sources = flat_shipping_sources(true);
        let transport = &sources
            .iter()
            .find(|(rel, _)| rel == TRANSPORT_FILE)
            .expect("the transport file moved: update this contract")
            .1;
        // Anti-vacuity: the transport itself makes these calls and builds
        // the client, so the needles (squeezed as the scan squeezes) match
        // real code.
        for needle in [
            ".remove_participant(",
            ".update_participant(",
            ".client.create_room(",
            "RoomClient::",
        ] {
            assert!(
                transport.contains(needle),
                "`{needle}` no longer matches the transport, so it proves nothing elsewhere"
            );
        }

        for (rel, compact) in &sources {
            if rel == TRANSPORT_FILE {
                continue;
            }
            for needle in ROOM_CLIENT {
                assert!(
                    !compact.contains(needle),
                    "{rel} calls the LiveKit room client (`{needle}`) outside the transport: \
                     go through a `VoiceClient` method, which runs under the D-5 deadline \
                     and breaker"
                );
            }
        }
    }

    /// AFK S-3 cleanup: the mapping-resolving SFU methods (`remove_user`,
    /// `mute_track`, `update_permissions_if_present`) and the RA-1 machinery
    /// behind the last one (`not_found_answer`, `NotFoundAnswer`,
    /// `push_primary_and_leg`) are gone, and stay gone: nowhere in the
    /// shipping workspace is any of them defined or called. Each resolved
    /// ONE connection of a user through the identity mapping, which names at
    /// most one; every caller now addresses the connections the SFU lists.
    /// A name must stand alone: `remove_user_if_present(` or
    /// `mute_track_identity(` never match.
    #[test]
    fn the_deleted_sfu_methods_stay_gone() {
        const GONE: [&str; 6] = [
            "remove_user(",
            "mute_track(",
            "update_permissions_if_present(",
            "not_found_answer(",
            "NotFoundAnswer",
            "push_primary_and_leg(",
        ];

        // Collapsed, not squeezed: `fn remove_user(` must keep the space that
        // makes the name stand alone.
        let sources = flat_shipping_sources(false);
        for (rel, flat) in &sources {
            for name in GONE {
                for (at, _) in flat.match_indices(name) {
                    let before = flat[..at].chars().next_back();
                    assert!(
                        before.is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
                        "`{name}` is back in {rel}"
                    );
                }
            }
        }
        // Anti-vacuity: the live twins the scan must NOT match are there, in
        // the form a definition of a deleted name would take.
        let transport = &sources
            .iter()
            .find(|(rel, _)| rel == "core/database/src/voice/voice_client.rs")
            .expect("the transport file moved: update this contract")
            .1;
        for twin in [
            "pub async fn remove_user_if_present(",
            "pub async fn mute_track_identity(",
        ] {
            assert!(
                transport.contains(twin),
                "`{twin}` is gone from the transport"
            );
        }
    }

    /// AFK S-3 S6B-1 (WC-2): the callers of the set-mode teardowns and of
    /// the sid-returning eviction, per shipping file, are exactly the ones
    /// that read `recorded_voice_connections` BEFORE their SFU listing (the
    /// WA-R ordering rule; each one's order is pinned at its own site). All
    /// three are `pub` and compile anywhere, so a new caller that lists
    /// first and reads `recorded` after would reintroduce WA-1 (a sibling
    /// recorded in between looks stale and is deleted while live) with every
    /// other test green. A new caller must be added here deliberately, with
    /// an order pin of its own. The counts are the shipping call sites
    /// (definitions, imports and comments excluded). Mutation: one more call
    /// site of any of the three in any shipping file.
    #[test]
    fn the_set_teardown_callers_are_exactly_the_record_first_ones() {
        let allowed: [(&str, Vec<(&str, usize)>); 3] = [
            (
                "tear_down_removed_connections(",
                vec![
                    ("core/database/src/voice/mod.rs", 1),
                    ("delta/src/routes/channels/voice_join.rs", 1),
                    ("delta/src/routes/servers/member_edit.rs", 1),
                ],
            ),
            (
                "delete_voice_connections(",
                vec![
                    ("core/database/src/voice/mod.rs", 1),
                    ("daemons/voice-ingress/src/api.rs", 1),
                ],
            ),
            (
                "remove_user_if_present_sids(",
                vec![
                    ("core/database/src/voice/mod.rs", 1),
                    ("delta/src/routes/channels/voice_join.rs", 1),
                    ("delta/src/routes/servers/member_edit.rs", 1),
                ],
            ),
        ];
        let sources = shipping_sources();
        for (needle, want) in allowed {
            let mut found: Vec<(&str, usize)> = sources
                .iter()
                .map(|(rel, shipping)| (rel.as_str(), call_sites(shipping, needle).len()))
                .filter(|(_, n)| *n > 0)
                .collect();
            found.sort();
            assert_eq!(
                found, want,
                "a caller of {needle} outside the record-first allowlist (WC-2)"
            );
        }
    }

    /// AFK S-3 S6B-2 (WBR-6): an eviction failure the removal answers with
    /// `Ok` (nothing of the user in Redis, the room never listed) is
    /// reported exactly once: through `to_internal_error()` here unless it
    /// is an `InternalError`, which was already reported where it arose.
    /// Mutations: the report deleted (a WARN only, no Sentry); the guard
    /// dropped (an `InternalError` reported twice).
    #[test]
    fn an_unheld_eviction_failure_is_reported_exactly_once() {
        let shipping = this_file_shipping();
        let body = flat_fn_body(&shipping, "fn report_unheld_eviction_failure(");
        assert!(
            body.ends_with(
                "if !matches!(error.error_type, revolt_result::ErrorType::InternalError) \
                 \u{7b} let _ = Err::<(), _>(error).to_internal_error(); \u{7d}"
            ),
            "{body}"
        );
        assert_eq!(body.matches("to_internal_error()").count(), 1, "{body}");
    }

    // ---- the AFK gate (AFK-channel plan D2 / audit CRITICAL-1) ----

    /// The gate at the level the SFU sees it: under an AFK designation NO
    /// permission bit and NO feature limit can put a source back, and the
    /// empty list it produces may only ever ship alongside
    /// `can_publish: false`.
    ///
    /// That pairing is the whole safety property. LiveKit reads an empty
    /// `can_publish_sources` as "no restriction"
    /// (`VideoGrant.GetCanPublishSource`, auth/grants.go), so an empty list
    /// shipped with `can_publish: true` grants EVERYTHING — the exact
    /// inversion of what the gate is for. This pins the pairing for the
    /// permission-sync and remote-control sets, by calling the functions that
    /// build them. It does NOT pin the join/move token: `create_token` builds
    /// its grant inline, and a copy of its expression here would stay green
    /// whatever the mint did (AFK Stage 6 F-B2). The token is pinned on a
    /// real mint, by `voice_client.rs`'s `afk_mint_tests`.
    #[test]
    fn afk_channel_yields_empty_sources_and_no_publish() {
        use super::remote_control_participant_permissions;

        let privileged = PermissionValue::from_raw(u64::MAX);
        let cases = [
            PermissionValue::from_raw(0),
            PermissionValue::from_raw(ChannelPermission::Listen as u64),
            PermissionValue::from_raw(
                ChannelPermission::Listen as u64
                    | ChannelPermission::Speak as u64
                    | ChannelPermission::Video as u64,
            ),
            // What `calculate_channel_permissions` hands a privileged account
            // and, through `calculate_server_permissions`, the server owner:
            // every bit, decided before any override is read. This is why D2
            // forbids implementing AFK as a permission denial.
            PermissionValue::from_raw(ChannelPermission::GrantAllSafe as u64),
            privileged,
        ];

        for permissions in cases {
            for video_limit in [false, true] {
                let limits = limits_with_video(video_limit);
                let sources = get_allowed_sources(&limits, permissions, afk());

                assert!(
                    sources.is_empty(),
                    "the AFK gate must drop every source (raw permissions \
                     {:?}, video limit {video_limit})",
                    permissions.has_channel_permission(ChannelPermission::Speak)
                );

                for can_listen in [false, true] {
                    let sync = voice_participant_permissions(can_listen, &sources);
                    assert!(!sync.can_publish);
                    assert!(sync.can_publish_sources.is_empty());
                    assert!(!sync.can_publish_data);
                    // Listening is NOT gated: an AFK member still hears the
                    // channel, they just cannot publish into it.
                    assert_eq!(sync.can_subscribe, can_listen);

                    // The remote-control accept path — audit CRITICAL-1. This
                    // is the set `control_respond` pushes, and ungated it is
                    // how a member in the AFK channel unmutes themselves with
                    // an in-product button.
                    let granted = remote_control_participant_permissions(can_listen, &sources);
                    assert!(
                        !granted.can_publish,
                        "accepting a remote-control offer must not re-grant publishing in the AFK channel"
                    );
                    assert!(granted.can_publish_sources.is_empty());
                }
            }
        }

        // Control: the same maximal permissions WITHOUT the gate do produce
        // sources, so nothing above passes for the wrong reason.
        let ungated = get_allowed_sources(&limits_with_video(true), privileged, not_afk());
        assert!(
            ungated.contains(&TrackSource::Microphone)
                && ungated.contains(&TrackSource::Camera)
                && ungated.contains(&TrackSource::ScreenShare)
                && ungated.contains(&TrackSource::ScreenShareAudio),
            "control: an undesignated channel still grants every source"
        );
        assert!(voice_participant_permissions(true, &ungated).can_publish);
    }

    /// A participant who is, right now, publishing on the microphone, on
    /// camera and on a screen share — the state the roster is rendering when
    /// the designation lands on their channel.
    fn publishing_everything(id: &str) -> UserVoiceState {
        UserVoiceState {
            id: id.to_string(),
            joined_at: Timestamp::UNIX_EPOCH,
            is_receiving: true,
            is_publishing: true,
            screensharing: true,
            camera: true,
            screen_video: true,
            recording: true,
            rc_capable: false,
            watching: false,
        }
    }

    /// Audit MEDIUM-7: under AFK the permission-sync must actually EMIT a
    /// `UserVoiceStateUpdate`.
    ///
    /// The fan-out in `sync_user_voice_permissions` is guarded by
    /// `if update_event != before`. Because D2 deliberately puts AFK outside
    /// the permission system, the permission bits are unchanged under an AFK
    /// designation — so if the roster flags were still computed from those
    /// bits, every field would stay `None`, the guard would hold and nothing
    /// would be sent. The SFU would kill the tracks while every other client
    /// kept rendering a camera tile and a speaking indicator.
    ///
    /// Audit HIGH-1 (wave-3 completion audit): the first version of this test
    /// RE-TYPED the four expressions instead of calling them. The auditor
    /// reverted the production derivation to the permission-bit form and the
    /// suite stayed byte-identically green — the defect this test is named for
    /// would have shipped. It now calls `roster_flags` and `roster_baseline`,
    /// the same two functions `sync_user_voice_permissions` calls, and holds no
    /// copy of their logic at all.
    ///
    /// HONEST SCOPE: it exercises the derivation, not the delivery. It does not
    /// call `sync_user_voice_permissions` itself, which needs Redis voice state
    /// and a LiveKit node; only a live two-seat leg proves seat B's roster
    /// actually drops the tile.
    #[test]
    fn afk_sync_forces_the_roster_flags_false_so_an_event_is_emitted() {
        const ID: &str = "01KX7HASD9FHBYA3XGKA5YACYX";

        // A privileged account with every bit and the video limit on, in the
        // AFK channel: the hardest case for the gate.
        let allowed_sources = get_allowed_sources(
            &limits_with_video(true),
            PermissionValue::from_raw(u64::MAX),
            afk(),
        );
        assert!(allowed_sources.is_empty());

        let state = publishing_everything(ID);
        let before = roster_baseline(ID);
        let update_event = roster_flags(ID, &allowed_sources, &state);

        assert_eq!(update_event.camera, Some(false));
        assert_eq!(update_event.screensharing, Some(false));
        assert_eq!(update_event.screen_video, Some(false));
        assert_eq!(update_event.is_publishing, Some(false));
        assert_ne!(
            update_event, before,
            "MEDIUM-7: the fan-out is guarded by `update_event != before`, so \
             a gate that leaves every field None emits nothing at all and the \
             roster keeps showing a camera tile for someone the SFU has \
             already silenced"
        );

        // `recording` stays out of the sync even though this participant has
        // it set — clearing it would delete the indicator without stopping the
        // recorder, which runs in the participant's own client. See
        // `roster_flags`.
        assert_eq!(update_event.recording, None);

        // Control 1: the SAME participant in an UNDESIGNATED channel keeps
        // every flag true, so the assertions above cannot pass for the wrong
        // reason (e.g. a `roster_flags` that always writes false).
        let ungated = get_allowed_sources(
            &limits_with_video(true),
            PermissionValue::from_raw(u64::MAX),
            not_afk(),
        );
        let unchanged = roster_flags(ID, &ungated, &state);
        assert_eq!(unchanged.camera, Some(true));
        assert_eq!(unchanged.screensharing, Some(true));
        assert_eq!(unchanged.screen_video, Some(true));
        assert_eq!(unchanged.is_publishing, Some(true));

        // Control 2: a participant publishing NOTHING produces exactly the
        // baseline even under the gate — there is nothing to correct, so the
        // guard correctly suppresses the event. This is what `!=` has to mean
        // for the assertion above to carry weight.
        let idle = UserVoiceState {
            is_publishing: false,
            screensharing: false,
            camera: false,
            screen_video: false,
            ..publishing_everything(ID)
        };
        assert_eq!(roster_flags(ID, &allowed_sources, &idle), before);
    }

    /// The D2 regression, end to end against a real database: the SERVER
    /// OWNER in the AFK channel gets no publish sources.
    ///
    /// The owner is the case an AFK-as-permission implementation cannot
    /// reach — `calculate_server_permissions` short-circuits for them before
    /// any override is read — so this is the test that distinguishes a real
    /// gate from a permission denial. It also covers both resolution paths
    /// (supplied server document vs. fetched) and asserts the gate binds
    /// ONLY the designated channel.
    ///
    /// Audit LOW-6 (wave-3 completion audit): this test used to assert the
    /// owner held `Speak`/`Video` on a FRESH server with no overrides, which
    /// is true with or without the short-circuit — so it demonstrated nothing
    /// about D2's premise. It now DENIES `Speak` to the default role on the
    /// channel itself, shows an ordinary member actually loses it there, and
    /// only then shows the owner keeps it regardless. That is the
    /// short-circuit observed rather than asserted, and it is why the mute has
    /// to be a hard gate applied after the calculus.
    #[tokio::test]
    async fn afk_gate_binds_the_server_owner() {
        use crate::{
            util::permissions::DatabasePermissionQuery, Channel, Member, PartialChannel,
            PartialServer, Server, User,
        };
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };
        use revolt_permissions::{calculate_channel_permissions, OverrideField};

        database_test!(|db| async move {
            let owner = User::create(&db, "AfkGateOwner".to_string(), None, None)
                .await
                .expect("`User`");

            let mut server = Server::create(
                &db,
                DataCreateServer {
                    name: "AfkGateServer".to_string(),
                    description: None,
                    nsfw: None,
                },
                &owner,
                false,
            )
            .await
            .expect("`Server`")
            .0;

            let voice_channel = |name: &str| {
                let name = name.to_string();
                DataCreateServerChannel {
                    channel_type: LegacyServerChannelType::Voice,
                    name,
                    ..Default::default()
                }
            };

            let mut afk_channel =
                Channel::create_server_channel(&db, &mut server, voice_channel("AFK"), true)
                    .await
                    .expect("`Channel`");
            let normal_channel =
                Channel::create_server_channel(&db, &mut server, voice_channel("General"), true)
                    .await
                    .expect("`Channel`");

            // An ordinary member, to show what a permission denial DOES bind.
            let member_user = User::create(&db, "AfkGateMember".to_string(), None, None)
                .await
                .expect("`User`");
            Member::create(&db, &server, &member_user, None)
                .await
                .expect("`Member`");

            // Control, before the override: the default role does grant Speak,
            // so losing it below is the override doing work and not the
            // server's defaults.
            let mut member_query =
                DatabasePermissionQuery::new(&db, &member_user).channel(&afk_channel);
            assert!(
                calculate_channel_permissions(&mut member_query)
                    .await
                    .has_channel_permission(ChannelPermission::Speak),
                "control: the default role grants Speak on a fresh voice channel"
            );

            // Deny Speak to the DEFAULT ROLE on the AFK channel itself — the
            // closest thing the permission system has to "AFK as a permission".
            afk_channel
                .update(
                    &db,
                    PartialChannel {
                        default_permissions: Some(OverrideField {
                            a: 0,
                            d: ChannelPermission::Speak as i64,
                        }),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("channel override");

            let mut member_query =
                DatabasePermissionQuery::new(&db, &member_user).channel(&afk_channel);
            assert!(
                !calculate_channel_permissions(&mut member_query)
                    .await
                    .has_channel_permission(ChannelPermission::Speak),
                "the channel override must actually deny Speak to an ordinary \
                 member — otherwise the owner assertion below proves nothing"
            );

            let mut query = DatabasePermissionQuery::new(&db, &owner).channel(&afk_channel);
            let permissions = calculate_channel_permissions(&mut query).await;
            assert!(
                permissions.has_channel_permission(ChannelPermission::Speak)
                    && permissions.has_channel_permission(ChannelPermission::Video),
                "D2, DEMONSTRATED: the same override that just stripped Speak \
                 from an ordinary member leaves the OWNER holding it, because \
                 `calculate_channel_permissions` returns GrantAllSafe for the \
                 server owner before any override is read. That is exactly why \
                 the AFK mute cannot be built as a permission denial"
            );

            let limits = owner.limits().await;

            // Control, before the designation exists: the owner publishes
            // normally, so the assertion below cannot pass vacuously.
            let ungated = get_allowed_sources(
                &limits,
                permissions,
                AfkGate::resolve(&db, &afk_channel, Some(&server))
                    .await
                    .expect("gate"),
            );
            assert!(
                !ungated.is_empty(),
                "control: an undesignated voice channel grants the owner sources"
            );

            server
                .update(
                    &db,
                    PartialServer {
                        afk_channel_id: Some(afk_channel.id().to_string()),
                        afk_timeout: Some(300),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("designation");

            // Both resolution paths: `Some(&server)` is the permission-sync
            // path (no fetch), `None` is every token-minting path.
            for server_arg in [Some(&server), None] {
                let gate = AfkGate::resolve(&db, &afk_channel, server_arg)
                    .await
                    .expect("gate");
                assert!(gate.denies_publishing());
                assert!(
                    get_allowed_sources(&limits, permissions, gate).is_empty(),
                    "D2 regression: the server OWNER may not publish in the AFK channel"
                );

                let other = AfkGate::resolve(&db, &normal_channel, server_arg)
                    .await
                    .expect("gate");
                assert!(
                    !other.denies_publishing(),
                    "the gate must bind ONLY the designated channel"
                );
                assert!(!get_allowed_sources(&limits, permissions, other).is_empty());
            }
        });
    }

    /// AFK Stage 6 F-B8: `AfkGate::resolve` uses a supplied `&Server` ONLY
    /// when it is the channel's own server, and otherwise fetches the right
    /// one. Against the Reference driver, with server documents built as
    /// values so each branch is observable:
    ///
    /// - a document with ANOTHER id is never read: it names the normal
    ///   channel as AFK and not the real one, and the answers are the
    ///   database's;
    /// - a document with the channel's OWN id is used as given, with no
    ///   fetch: a copy of the server from before the designation answers
    ///   "not AFK" for the channel the database says is AFK.
    ///
    /// Mutations: the `server.id == server_id` guard dropped (the foreign
    /// document is trusted), or the supplied document never used (always
    /// fetch). On the shared Redis-test runtime (see `tests::rt`).
    #[test]
    fn afk_gate_uses_a_supplied_server_only_when_it_is_the_channels_own() {
        super::tests::rt()
            .block_on(afk_gate_uses_a_supplied_server_only_when_it_is_the_channels_own_case())
    }

    async fn afk_gate_uses_a_supplied_server_only_when_it_is_the_channels_own_case() {
        use crate::{Channel, Database, PartialServer, Server, User};
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };

        let db = Database::Reference(Default::default());
        let owner = User::create(&db, "AfkGateGuardOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "AfkGateGuardServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;
        let voice_channel = |name: &str| DataCreateServerChannel {
            channel_type: LegacyServerChannelType::Voice,
            name: name.to_string(),
            ..Default::default()
        };
        let afk_channel =
            Channel::create_server_channel(&db, &mut server, voice_channel("AFK"), true)
                .await
                .expect("`Channel`");
        let normal_channel =
            Channel::create_server_channel(&db, &mut server, voice_channel("General"), true)
                .await
                .expect("`Channel`");

        // Taken BEFORE the designation: the server's own id, no AFK channel.
        let before_designation = server.clone();

        server
            .update(
                &db,
                PartialServer {
                    afk_channel_id: Some(afk_channel.id().to_string()),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("designation");

        // Another server's document, claiming the NORMAL channel is AFK.
        let foreign = Server {
            id: "01KX7J0000FOREIGNSERVER000".to_string(),
            afk_channel_id: Some(normal_channel.id().to_string()),
            ..server.clone()
        };
        async fn denies(db: &Database, channel: &Channel, supplied: Option<&Server>) -> bool {
            AfkGate::resolve(db, channel, supplied)
                .await
                .expect("gate")
                .denies_publishing()
        }

        assert!(
            denies(&db, &afk_channel, Some(&foreign)).await,
            "a foreign document must not be read: the database designates this channel"
        );
        assert!(
            !denies(&db, &normal_channel, Some(&foreign)).await,
            "a foreign document must not be read: it is the one naming this channel"
        );

        assert!(
            !denies(&db, &afk_channel, Some(&before_designation)).await,
            "the channel's own server, when supplied, is used as given (no fetch)"
        );
        assert!(
            denies(&db, &afk_channel, Some(&server)).await && denies(&db, &afk_channel, None).await,
            "control: the current document and the fetch both designate it"
        );
    }

    /// The structural defense against audit CRITICAL-1 recurring.
    ///
    /// The draft of this feature claimed `get_allowed_sources` was "the
    /// single helper feeding both the join token and the live re-sync". It
    /// is not: there are FOUR production call sites, and the two that were
    /// missed are the remote-control grant and revoke paths — the ones that
    /// let a member in the AFK channel unmute themselves by accepting an
    /// offer. The failure mode is not exotic: a lane that changes the
    /// signature and cannot touch those files takes the cheapest fix
    /// available to it.
    ///
    /// So the gate is a VALUE with no public constructor other than
    /// `AfkGate::resolve`, and this test pins the remaining textual half:
    /// every call site constructs one INLINE (the same discipline
    /// `remote_control_teardown_restores_the_sync_permission_set` applies to
    /// permission constructors), the inventory of call sites is fixed, the
    /// test-only constructor appears in no shipping source, and the FIFTH
    /// publish-rights path — the Android screen leg, which hard-codes its
    /// grant and never consults the helper — carries its own gate.
    ///
    /// Audit LOW-2 (wave-3 completion audit): the inventory used to
    /// `dedup()` to a set of FILES, which collapses a file to one entry and
    /// so cannot see a SECOND call site added to an already-listed file. The
    /// realistic case is this very file, the one lane file with shipping code
    /// BELOW its test module. It now pins a COUNT PER FILE, so a second site
    /// anywhere is a failure, not a silent pass.
    #[test]
    fn afk_gate_has_no_opt_out_at_any_call_site() {
        const NEEDLE: &str = "get_allowed_sources(";
        const CONSTRUCTOR: &str = "AfkGate::resolve(";
        const LEG_FILE: &str = "core/database/src/voice/voice_client.rs";
        // Sorted, and with the number of call sites each file is allowed to
        // hold. Every one of these is a path that mints or re-pushes publish
        // rights; adding a fifth — or a second one inside a file already
        // here — means deciding, deliberately, that it is gated too.
        const EXPECTED: [(&str, usize); 4] = [
            ("core/database/src/voice/mod.rs", 1), // sync_user_voice_permissions
            ("core/database/src/voice/remote_control.rs", 1), // RC revoke
            (LEG_FILE, 1),                         // the join token
            ("delta/src/routes/channels/remote_control.rs", 1), // RC grant
        ];

        let sources = shipping_sources();
        let mut callers: Vec<(&str, usize)> = Vec::new();

        for (rel, shipping) in &sources {
            let mut count = 0usize;
            for at in call_sites(shipping, NEEDLE) {
                let args = call_args(shipping, at + NEEDLE.len() - 1);
                assert!(
                    args.contains(CONSTRUCTOR),
                    "the get_allowed_sources call site in {rel} does not \
                     construct its AfkGate inline — pass \
                     `AfkGate::resolve(db, channel, server).await?` directly \
                     as the argument so this contract can see it. There is \
                     no other shipping constructor, and that is deliberate: \
                     audit CRITICAL-1 is what happens when a call site can \
                     opt out of this gate"
                );
                count += 1;
            }
            if count > 0 {
                callers.push((rel.as_str(), count));
            }
        }

        callers.sort_unstable();
        assert_eq!(
            callers, EXPECTED,
            "the inventory of publish-rights paths changed. Four production \
             call sites, one per file, feed LiveKit grants through \
             get_allowed_sources; a new one — including a second one in a \
             file already listed — is a new way to publish in the AFK channel"
        );

        for (rel, shipping) in &sources {
            assert!(
                !shipping.contains("from_raw_for_tests("),
                "{rel} reaches for the test-only AfkGate constructor — that \
                 is the caller-supplied bool D2 forbids"
            );
        }

        // The fifth path. `create_screen_leg_token` spells its grant out
        // instead of deriving it (its own doc comment says so), so the scan
        // above cannot see it: a phone would screen-share into the AFK
        // channel while every WebView in the room was refused.
        let leg = &sources
            .iter()
            .find(|(rel, _)| rel == LEG_FILE)
            .expect("the screen-leg token file moved — move this contract with it")
            .1;
        let fn_start = leg
            .find("fn create_screen_leg_token")
            .expect("create_screen_leg_token left the file — move this contract with it");
        let fn_end = fn_start
            + leg[fn_start..]
                .find("\n    pub async fn ")
                .unwrap_or(leg.len() - fn_start);
        assert!(
            leg[fn_start..fn_end].contains(CONSTRUCTOR),
            "the Android screen leg hard-codes can_publish: true plus both \
             screen sources and never consults get_allowed_sources — it must \
             carry its own AFK gate"
        );
    }

    /// The braced body of a block whose opening brace sits at byte `open`,
    /// exclusive of the braces themselves. Brace-matching on the raw text
    /// (unlike `strip_test_items`, which reads `blanked` text): callers must
    /// keep braces BALANCED inside strings and comments in the code being
    /// scanned.
    fn braced_body(shipping: &str, open: usize) -> &str {
        let mut depth = 0i64;
        for (i, ch) in shipping[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &shipping[open + 1..open + i];
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced braces in a block at byte {open}");
    }

    /// Wave-3b. REGRESSION TEST for the sync seam, and a STRUCTURAL one -
    /// read what it does and does not prove before trusting it.
    ///
    /// It proves: every route that writes `Server.afk_channel_id` into a
    /// `PartialServer` also calls `sync_afk_designation_change`, and nothing
    /// else in the workspace calls that helper. That is exactly the shape of
    /// the defect it exists for. `server_edit` re-synced both sides of a
    /// designation change from the day the field landed; `channel_create`
    /// wrote the same field and took no `voice_client` at all, so once the
    /// enforcement gate went in, creating a new AFK channel left the
    /// occupants of the old one muted at the SFU indefinitely. Two writers of
    /// one server-level invariant with different post-write behavior.
    ///
    /// It does NOT prove that the re-sync reaches the SFU, that the POST-update
    /// server document is the one handed to the helper, or that a participant's
    /// grant actually changes. None of that is reachable from a unit test here:
    /// `sync_voice_permissions` goes through `get_channel_node`, which is a
    /// Redis read, and the delta Rocket harness cannot boot on this box. Only a
    /// live two-seat leg settles those.
    ///
    /// The scan is scoped to `delta/src/routes/` deliberately. The bridge
    /// conversions in `util/bridge/v0.rs` also mention `afk_channel_id` inside
    /// a `PartialServer` literal and are mechanical field-for-field copies,
    /// not writers; and the route layer is the only layer that holds a
    /// `VoiceClient` to sync with.
    ///
    /// KNOWN FALSE NEGATIVE, stated rather than papered over: the writer scan
    /// only recognizes the field inside a `PartialServer` struct literal. A
    /// route that built the partial some other way - `PartialServer::default()`
    /// then a field assignment, or a spread from a partial constructed
    /// elsewhere - would write the designation without this test noticing.
    /// Both current writers use the literal form, and so does every other
    /// `PartialServer` construction in the route layer.
    #[test]
    fn every_afk_designation_writer_resyncs_both_sides() {
        // The opening brace is written as an escape because
        // `strip_test_items`, which brace-matches this very module to cut it
        // out of the scan, used to count braces inside string literals too: a
        // bare opening brace in a string literal inside a test module silently
        // over-stripped the file and broke the sibling contract tests - which
        // is exactly what it did. It reads `blanked` text now (merge slice
        // S6RM-5); the escape stays.
        const PARTIAL: &str = "PartialServer \u{7b}";
        const FIELD: &str = "afk_channel_id";
        const SYNC: &str = "sync_afk_designation_change(";
        const ROUTES: &str = "delta/src/routes/";
        // Sorted. A third writer of this field is a third chance to leave a
        // room stuck; adding one means wiring this call too.
        const EXPECTED: [&str; 2] = [
            "delta/src/routes/servers/channel_create.rs",
            "delta/src/routes/servers/server_edit.rs",
        ];

        let sources = shipping_sources();
        let mut writers: Vec<&str> = Vec::new();

        for (rel, shipping) in &sources {
            if !rel.starts_with(ROUTES) {
                continue;
            }

            for at in shipping.match_indices(PARTIAL).map(|(at, _)| at) {
                // the opening brace of the struct literal
                let open = at + PARTIAL.len() - 1;
                if braced_body(shipping, open).contains(FIELD) {
                    writers.push(rel.as_str());
                }
            }
        }

        writers.sort_unstable();
        writers.dedup();
        assert_eq!(
            writers, EXPECTED,
            "the inventory of routes writing Server.afk_channel_id changed"
        );

        for rel in &writers {
            let shipping = &sources
                .iter()
                .find(|(candidate, _)| candidate == rel)
                .expect("the writer was just found in this same scan")
                .1;
            assert!(
                !call_sites(shipping, SYNC).is_empty(),
                "{rel} writes Server.afk_channel_id but never calls \
                 sync_afk_designation_change. The designation moves, the \
                 enforcement gate reads it off the server document, and \
                 everyone already sitting in the OUTGOING channel keeps the \
                 LiveKit grant they were minted - muted at the SFU with no \
                 UserVoiceStateUpdate until some unrelated role edit happens \
                 to trigger a sync"
            );
        }

        // ...and nothing else calls it. The helper exists because the rule
        // had two divergent copies; a caller outside the writer set would
        // mean it has grown a third meaning.
        // `call_sites` already excludes the definition line itself, so the
        // defining file is scanned like any other.
        let mut callers: Vec<&str> = sources
            .iter()
            .flat_map(|(rel, shipping)| {
                call_sites(shipping, SYNC)
                    .into_iter()
                    .map(move |_| rel.as_str())
            })
            .collect();
        callers.sort_unstable();
        callers.dedup();
        assert_eq!(
            callers, EXPECTED,
            "sync_afk_designation_change gained or lost a caller"
        );
    }

    /// The route both mover-side gates live in.
    const MEMBER_EDIT: &str = "delta/src/routes/servers/member_edit.rs";

    /// The self-move exemption both gates are written under, verbatim.
    ///
    /// Pinned as TEXT because both of its plausible one-token reversals are
    /// invisible to everything else that runs: flipping `!=` to `==` leaves a
    /// gate that only ever fires on a self-move, i.e. never on the action it
    /// exists to refuse, and no compiler, lint or executable test says a word.
    const EXEMPTION: &str = "member.id.user != user.id";

    /// The nearest enclosing `if` condition before byte `at`, as written.
    ///
    /// Textual, like the rest of this scanner: it reads back to the last
    /// `if ` and returns what sits between that and the call, minus the
    /// opening brace. Both gates are therefore written with their exemption
    /// as the INNERMOST condition and no comment between it and the call —
    /// if that changes, this stops being able to see the guard, and the
    /// assertion below says so rather than passing vacuously.
    fn nearest_guard(shipping: &str, at: usize) -> &str {
        const IF: &str = "if ";
        let before = &shipping[..at];
        let start = before
            .rfind(IF)
            .unwrap_or_else(|| panic!("no enclosing `if` before byte {at} in the scanned source"));

        // The brace is an escape, never a literal, for the same reason the
        // gate scan below writes its one that way (`strip_test_items` used to
        // count braces inside literals).
        before[start + IF.len()..]
            .trim_end()
            .trim_end_matches('\u{7b}')
            .trim_end()
    }

    /// Wave-5a. STRUCTURAL pin on one of the member-move route's MOVER-side
    /// gates — shared by the destination gate and the source gate, which have
    /// the same shape and the same ways of being reverted.
    ///
    /// `admit_voice_move` answers for the TARGET and deliberately knows
    /// nothing about an acting user — the AFK sweep has none. Whether the
    /// person who ASKED for the move may reach into a channel is route
    /// policy, and it has to be evaluated channel-scoped: the route's other
    /// `MoveMembers` check is computed server-scoped and never reads a
    /// channel override, so a role denied on a private voice channel passes
    /// it anyway. That gate was deleted once already, and nothing caught it,
    /// because the delta route harness needs RabbitMQ and cannot boot on the
    /// build box — which is exactly why the pin lives over here, in a suite
    /// that runs.
    ///
    /// It proves: `member_edit` still defines the gate, it is still called
    /// exactly once, its body still computes channel-scoped permissions and
    /// demands both `MoveMembers` and `ViewChannel`, the call still passes
    /// the ACTING user (`&user`) and the channel the gate is named for, and
    /// the call still sits under the self-move exemption written the right
    /// way round.
    ///
    /// The last two are why the arguments and the guard are compared
    /// LITERALLY rather than merely searched for. A re-audit ran both
    /// one-token reverts against the presence-only version of this pin —
    /// `!=` to `==`, and `&user` to `&target_user` — and every gate in the
    /// tree stayed green: the first makes the gate run only for the case it
    /// exempts, the second asks whether the person being moved may move
    /// themselves, which they always may. Nothing else in the workspace can
    /// see either.
    ///
    /// It does NOT prove that the gate runs before the member is mutated, or
    /// that any particular request is refused.
    /// `move_is_refused_when_the_mover_is_denied_the_destination` and
    /// `move_needs_move_members_on_the_source_channel` cover those, wherever
    /// the route harness can run; `a_source_the_mover_cannot_see_is_answered_as_no_call`
    /// covers a source the mover cannot see (merge slice FXA-1: no call, not
    /// a refusal).
    fn assert_member_edit_gates_the_mover(gate: &str, expected_args: [&str; 3], end: &str) {
        const REQUIRED: [&str; 3] = [
            "calculate_channel_permissions(",
            "ChannelPermission::MoveMembers",
            "ChannelPermission::ViewChannel",
        ];

        let sources = shipping_sources();
        let shipping = &sources
            .iter()
            .find(|(rel, _)| rel == MEMBER_EDIT)
            .unwrap_or_else(|| panic!("{MEMBER_EDIT} is not in the workspace scan"))
            .1;

        let definition = shipping.find(&format!("fn {gate}")).unwrap_or_else(|| {
            panic!(
                "{MEMBER_EDIT} no longer defines a mover-side {end} gate. The \
                 server-scoped MoveMembers check is not a substitute: it never \
                 reads a channel override, so a moderator denied on a private \
                 voice channel can still reach into it"
            )
        });

        // `call_sites` skips the `fn` line, so the definition is not a call.
        let calls = call_sites(shipping, gate);
        assert_eq!(
            calls.len(),
            1,
            "the mover-side {end} gate must be called exactly once in \
             {MEMBER_EDIT} — an uncalled gate is the same defect with more code"
        );

        // The opening brace is written as an escape for the same reason
        // `every_afk_designation_writer_resyncs_both_sides` writes its one
        // that way: `strip_test_items` used to count braces inside literals,
        // and a lone brace here over-stripped the file and broke every sibling
        // contract test.
        let open = definition
            + shipping[definition..]
                .find('\u{7b}')
                .expect("the gate has a body");
        let body = braced_body(shipping, open);

        for needle in REQUIRED {
            assert!(
                body.contains(needle),
                "the mover-side {end} gate in {MEMBER_EDIT} no longer mentions \
                 {needle}. It has to compute the acting user's permissions \
                 against the {end} channel and demand both MoveMembers and \
                 ViewChannel there"
            );
        }

        // The call's argument list, verbatim. `&user` is the acting user;
        // `&target_user` is the person being moved, and a gate pointed at
        // them asks whether they may move themselves, which is always yes.
        let args: Vec<&str> = call_args(shipping, calls[0] + gate.len() - 1)
            .split(',')
            .map(str::trim)
            .filter(|argument| !argument.is_empty())
            .collect();
        assert_eq!(
            args,
            expected_args.to_vec(),
            "the mover-side {end} gate in {MEMBER_EDIT} is no longer called \
             with the acting user and the {end} channel. It must evaluate the \
             person who ASKED for the move, not the person being moved"
        );

        // ...and it still only runs when there is somebody to moderate.
        assert_eq!(
            nearest_guard(shipping, calls[0]),
            EXEMPTION,
            "the mover-side {end} gate in {MEMBER_EDIT} is no longer guarded by \
             `{EXEMPTION}`. Reversed, the gate runs ONLY for a self-move and \
             never for the action it exists to refuse; removed, it refuses \
             members leaving their own call"
        );
    }

    #[test]
    fn the_member_move_route_gates_the_mover_on_the_destination_channel() {
        assert_member_edit_gates_the_mover(
            "assert_mover_may_move_into(",
            ["db", "&user", "&channel"],
            "destination",
        );
    }

    /// The other end of the same action, and the one that was missing.
    ///
    /// Gating only the destination let a moderator denied on a private voice
    /// channel pull members OUT of it into a channel they do control. The
    /// server-scoped `MoveMembers` check reads no channel override at either
    /// end, so the reasoning is symmetric and so is the gate. A source the
    /// mover cannot even VIEW never reaches this gate (operator ruling
    /// 2026-09-28, FXA-1): the route answers a target sitting there exactly
    /// as it answers a target in no call (`mover_can_see_source`), so neither
    /// a refusal nor the outcome tells the mover who sits in it.
    #[test]
    fn the_member_move_route_gates_the_mover_on_the_source_channel() {
        assert_member_edit_gates_the_mover(
            "assert_mover_may_move_out_of(",
            ["db", "&user", "&source"],
            "source",
        );
    }

    // ---- the occupancy cap's already-present exemption --------------------

    /// The `max_users` cap must not refuse somebody who is already in the
    /// room it is capping.
    ///
    /// The two other call-admission caps (`video_cap_would_refuse`,
    /// `mls_cap_would_refuse`) have carried this exemption from the day they
    /// landed; the occupancy cap did not. An AFK channel with `max_users: 5`
    /// holding five idle members answered `CannotJoinCall` for all five, on
    /// every sweep tick, and on the route it turned "move X to where X
    /// already is" into a 400 as soon as the channel was capped and full.
    #[test]
    fn the_occupancy_cap_exempts_somebody_already_in_the_room() {
        const MAX: usize = 5;
        let occupants: Vec<String> = (0..MAX).map(|i| format!("occupant-{i}")).collect();

        // A newcomer at the cap is refused...
        assert!(super::occupancy_cap_refuses(
            &occupants, MAX, "newcomer", false
        ));

        // ...and waved in by ManageChannel, as at the join front door.
        assert!(!super::occupancy_cap_refuses(
            &occupants, MAX, "newcomer", true
        ));

        // Every occupant is exempt: admitting them cannot grow the roster.
        for occupant in &occupants {
            assert!(
                !super::occupancy_cap_refuses(&occupants, MAX, occupant, false),
                "an occupant of the destination must not be refused by the \
                 destination's own occupancy cap"
            );
        }

        // Below the cap, nobody is refused.
        assert!(!super::occupancy_cap_refuses(
            &occupants[..MAX - 1],
            MAX,
            "newcomer",
            false
        ));
    }

    // ---- the voice-move admission gates ----------------------------------
    //
    // These exercise `admit_voice_move`, the side-effect-free half of
    // `move_user_to_voice_channel_expecting`, against a real database and the
    // real permission calculus. They stop short of the call-admission caps and of
    // the move itself: both read Redis, which these tests do not have,
    // whereas every gate below is answerable from the channel document and
    // the calculus alone.

    /// A server, its owner, and one ordinary member of it.
    #[cfg(test)]
    async fn voice_move_fixture(db: &crate::Database) -> (crate::Server, crate::User, crate::User) {
        use crate::{Member, Server, User};
        use revolt_models::v0::DataCreateServer;

        let owner = User::create(db, "VoiceMoveOwner".to_string(), None, None)
            .await
            .expect("`User`");

        let server = Server::create(
            db,
            DataCreateServer {
                name: "VoiceMoveServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;

        let member_user = User::create(db, "VoiceMoveMember".to_string(), None, None)
            .await
            .expect("`User`");
        Member::create(db, &server, &member_user, None)
            .await
            .expect("`Member`");

        (server, owner, member_user)
    }

    /// A destination that is not a voice channel must be refused.
    ///
    /// The join front door has always checked this; the move path never did,
    /// and its only fixture happened to be a real voice channel, so nothing
    /// ever noticed. A text-channel destination reached the LiveKit machinery
    /// and opened a room named after a text channel.
    #[tokio::test]
    async fn moving_into_a_text_channel_is_refused() {
        use crate::Channel;
        use revolt_models::v0::{DataCreateServerChannel, LegacyServerChannelType};
        use revolt_result::ErrorType;

        database_test!(|db| async move {
            let (mut server, _owner, member_user) = voice_move_fixture(&db).await;

            let make = |channel_type, name: &str| DataCreateServerChannel {
                channel_type,
                name: name.to_string(),
                ..Default::default()
            };

            let voice = Channel::create_server_channel(
                &db,
                &mut server,
                make(LegacyServerChannelType::Voice, "Voice"),
                true,
            )
            .await
            .expect("`Channel`");

            let text = Channel::create_server_channel(
                &db,
                &mut server,
                make(LegacyServerChannelType::Text, "General"),
                true,
            )
            .await
            .expect("`Channel`");

            // Under every policy (merge slice: the refusal is not a Connect
            // or cap rule the policy relaxes).
            for policy in [
                super::MovePolicy::Moderator,
                super::MovePolicy::SelfMove {
                    request_session: None,
                },
                super::MovePolicy::Sweep,
            ] {
                // Control: the same member, the same server, a real voice
                // channel — admissible. So the refusal below is about the
                // channel type and nothing else.
                super::admit_voice_move(&db, &member_user, &voice, policy)
                    .await
                    .expect("control: a plain member may be moved into a voice channel");

                let refused = super::admit_voice_move(&db, &member_user, &text, policy)
                    .await
                    .expect_err("a text channel is not somewhere anyone can be moved");
                assert!(
                    matches!(refused.error_type, ErrorType::NotAVoiceChannel),
                    "{policy:?}: expected NotAVoiceChannel, got {:?}",
                    refused.error_type
                );
            }
        });
    }

    /// `Connect` is evaluated against the TARGET, never against whoever asked
    /// for the move.
    ///
    /// It used to be calculated from the acting user's query, so a
    /// moderator's own Connect waved the target into a channel the target is
    /// denied — and a sweep, which has no acting user at all, had nothing to
    /// evaluate. The OWNER stands in for the moderator here on purpose: the
    /// calculus short-circuits to GrantAllSafe for them before any override is
    /// read, so a mover-side check passes unconditionally and this test is
    /// unpinnable any other way.
    #[tokio::test]
    async fn connect_is_evaluated_against_the_target_not_the_mover() {
        use crate::{util::permissions::DatabasePermissionQuery, Channel, PartialChannel};
        use revolt_models::v0::{DataCreateServerChannel, LegacyServerChannelType};
        use revolt_permissions::{calculate_channel_permissions, OverrideField};
        use revolt_result::ErrorType;

        database_test!(|db| async move {
            let (mut server, owner, member_user) = voice_move_fixture(&db).await;

            let mut destination = Channel::create_server_channel(
                &db,
                &mut server,
                DataCreateServerChannel {
                    channel_type: LegacyServerChannelType::Voice,
                    name: "Restricted".to_string(),
                    ..Default::default()
                },
                true,
            )
            .await
            .expect("`Channel`");

            // Admission never reads the request session (the move checks
            // it before admission), so any value does here.
            let self_move = super::MovePolicy::SelfMove {
                request_session: None,
            };

            // Control, before the override: the member is admissible, so the
            // refusal below is the override doing the work.
            super::admit_voice_move(&db, &member_user, &destination, self_move)
                .await
                .expect("control: the member may be moved here before the denial");

            destination
                .update(
                    &db,
                    PartialChannel {
                        default_permissions: Some(OverrideField {
                            a: 0,
                            d: ChannelPermission::Connect as i64,
                        }),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("channel override");

            // The mover's own standing is untouched: the owner still holds
            // Connect here, which is exactly what made the old check pass.
            let mut owner_query = DatabasePermissionQuery::new(&db, &owner).channel(&destination);
            assert!(
                calculate_channel_permissions(&mut owner_query)
                    .await
                    .has_channel_permission(ChannelPermission::Connect),
                "control: the owner is waved through by GrantAllSafe, so a \
                 mover-side Connect check could not refuse this move"
            );

            // Where Connect is required at all (a self-move, merge slice
            // RT-3), it is the TARGET's.
            let refused = super::admit_voice_move(&db, &member_user, &destination, self_move)
                .await
                .expect_err("the TARGET is denied Connect on the destination");
            assert!(
                matches!(refused.error_type, ErrorType::MissingPermission { .. }),
                "expected MissingPermission, got {:?}",
                refused.error_type
            );

            // Ruling D0-1 (and 09-27 for the sweep): a moderator's move, and
            // the sweep's, do not need the target's Connect. The target can
            // still view the channel, which every policy requires.
            for policy in [super::MovePolicy::Moderator, super::MovePolicy::Sweep] {
                super::admit_voice_move(&db, &member_user, &destination, policy)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("{policy:?}: no target Connect is needed, got {error:?}")
                    });
            }
        });
    }

    /// A target who cannot VIEW the destination is never moved into it.
    ///
    /// AN OUTCOME PIN, NOT A CONTROL FOR THE `ViewChannel` GATE — read that
    /// before trusting it as one. On a server channel the permission calculus
    /// revokes every bit once `ViewChannel` is missing, so `Connect` is gone
    /// for the same member and deleting the explicit `ViewChannel` line from
    /// `admit_voice_move` leaves this test green. What it holds is the
    /// OUTCOME the client depends on: bonfire filters an unviewable channel
    /// out of `Ready`, so a target moved into one is told to open a channel
    /// their client does not have — out of the call they were in, with no
    /// route back. The move is not a join; they never chose this destination,
    /// so nothing may leave them there.
    #[tokio::test]
    async fn moving_a_target_who_cannot_view_the_destination_is_refused() {
        use crate::{Channel, PartialChannel};
        use revolt_models::v0::{DataCreateServerChannel, LegacyServerChannelType};
        use revolt_permissions::OverrideField;
        use revolt_result::ErrorType;

        database_test!(|db| async move {
            let (mut server, _owner, member_user) = voice_move_fixture(&db).await;

            let mut destination = Channel::create_server_channel(
                &db,
                &mut server,
                DataCreateServerChannel {
                    channel_type: LegacyServerChannelType::Voice,
                    name: "Hidden".to_string(),
                    ..Default::default()
                },
                true,
            )
            .await
            .expect("`Channel`");

            const POLICIES: [super::MovePolicy<'static>; 3] = [
                super::MovePolicy::Moderator,
                super::MovePolicy::SelfMove {
                    request_session: None,
                },
                super::MovePolicy::Sweep,
            ];

            // Control, before the override: admissible, so the refusal below
            // is the override doing the work.
            for policy in POLICIES {
                super::admit_voice_move(&db, &member_user, &destination, policy)
                    .await
                    .expect("control: the member may be moved here before the denial");
            }

            destination
                .update(
                    &db,
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
                .expect("channel override");

            // Under EVERY policy. For a moderator or the sweep (which need
            // no Connect since the merge slice) the explicit `ViewChannel`
            // line is the only thing refusing this, so for them this is a
            // real control of that line, not just an outcome pin.
            for policy in POLICIES {
                let refused = super::admit_voice_move(&db, &member_user, &destination, policy)
                    .await
                    .expect_err("the TARGET cannot view the destination");
                assert!(
                    matches!(refused.error_type, ErrorType::MissingPermission { .. }),
                    "{policy:?}: expected MissingPermission, got {:?}",
                    refused.error_type
                );
            }
        });
    }

    /// Merge slice RT-3 / ruling D0-2: a moderator's move and the sweep's
    /// bypass the destination's `max_users`; a self-move obeys it. The roster
    /// is Redis, so this runs on the shared runtime with a real roster entry
    /// filling a one-seat channel.
    #[test]
    fn only_a_self_move_obeys_the_destination_cap() {
        super::tests::rt().block_on(async {
            use crate::{Channel, Database};
            use revolt_models::v0::{
                DataCreateServerChannel, LegacyServerChannelType, VoiceInformation,
            };
            use revolt_result::ErrorType;

            let db = Database::Reference(Default::default());
            let (mut server, owner, member_user) = voice_move_fixture(&db).await;
            let capped = Channel::create_server_channel(
                &db,
                &mut server,
                DataCreateServerChannel {
                    channel_type: LegacyServerChannelType::Voice,
                    name: "OneSeat".to_string(),
                    voice: Some(VoiceInformation {
                        max_users: Some(1),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                true,
            )
            .await
            .expect("`Channel`");
            let seat = super::UserVoiceChannel::from_channel(&capped);
            super::create_voice_state(&seat, &owner.id, super::Timestamp::now_utc())
                .await
                .expect("the one seat is taken");

            let self_move = super::MovePolicy::SelfMove {
                request_session: None,
            };
            let refused = super::admit_voice_move(&db, &member_user, &capped, self_move).await;
            let moderator =
                super::admit_voice_move(&db, &member_user, &capped, super::MovePolicy::Moderator)
                    .await;
            let sweep =
                super::admit_voice_move(&db, &member_user, &capped, super::MovePolicy::Sweep)
                    .await;

            super::delete_voice_state(&seat, &owner.id)
                .await
                .expect("cleanup");

            assert!(
                matches!(
                    refused.map(|_| ()).map_err(|error| error.error_type),
                    Err(ErrorType::CannotJoinCall)
                ),
                "a self-move into a full channel is refused"
            );
            assert!(moderator.is_ok(), "a moderator's move bypasses max_users");
            assert!(sweep.is_ok(), "the sweep moves under moderator rules");
        });
    }
}

/// Re-sync one user's LiveKit grant in `channel`.
///
/// Roster-driven like [`sync_voice_permissions`] (AFK S-3 D-4), with the
/// same outcome table, but through its OWN single listing of the room
/// ([`SyncConnections::ListRoom`]): taken after the member and role checks,
/// filtered to this user by [`roster_connections`], and the grant pushed to
/// every connection it names. A failed listing is an `Err` (ERROR + Sentry
/// inside `list_participants_reported`).
///
/// A member who has gone (the member document is deleted, or the SFU lists
/// no connection of theirs) is still an `Err` here, of the same type as
/// before AFK Stage 6 F-A1 (`NotFound`, `InternalError`): this single-user
/// entry point keeps its contract for its direct caller (`member_edit`). The
/// room-wide [`sync_voice_permissions`] uses the classified form and skips
/// such a member instead. A real SFU failure on the push is still logged at
/// ERROR and reported to Sentry (`update_permissions_identity_if_present`,
/// under `update_permissions_connections`).
pub async fn sync_user_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user: &User,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> Result<()> {
    match sync_user_voice_permissions_classified(
        db,
        voice_client,
        node,
        user,
        SyncConnections::ListRoom,
        channel,
        server,
        role_id,
    )
    .await
    {
        MemberSync::Synced => Ok(()),
        // The error this entry point returned before AFK Stage 6 F-A1
        // (`NotFound` for a deleted member, `InternalError` for a
        // participant the SFU does not have), but no longer a silent one:
        // the `InternalError` is built here, not by `to_internal_error()`,
        // so nothing else logs it (re-audit RA-5).
        MemberSync::Gone(error) => {
            log::warn!(
                "permission sync of {} in {}: the member is no longer there to sync \
                 ({:?}); answering with the error this entry point always returned",
                user.id,
                channel.id(),
                error.error_type
            );
            Err(error)
        }
        MemberSync::Failed(error) => Err(error),
    }
}

/// [`sync_user_voice_permissions`], with its outcome classified for the
/// room-wide sync (see [`MemberSync`]).
#[allow(clippy::too_many_arguments)]
async fn sync_user_voice_permissions_classified(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user: &User,
    connections: SyncConnections<'_>,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> MemberSync<revolt_result::Error> {
    match push_user_voice_permissions(
        db,
        voice_client,
        node,
        user,
        connections,
        channel,
        server,
        role_id,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => MemberSync::Failed(error),
    }
}

/// The body of [`sync_user_voice_permissions`]. Every `?` in it is a real
/// failure; the ways a member can be gone are returned as
/// `Ok(MemberSync::Gone(..))`, each at the step that finds it out.
///
/// The outcome table (AFK S-3 D-4), once the member and role checks pass:
///
/// | voice state | connections listed | outcome |
/// |---|---|---|
/// | no | none | `Synced`: nothing to push |
/// | no | some | the grant is pushed to them, NO state is written, no roster event, WARN (heals F-2) |
/// | yes | none | `Gone`: nothing is left to push to |
/// | yes | some | the roster flags are written, then the grant is pushed to them |
///
/// A push every connection answers not_found (all left since the listing)
/// is `Gone`; any other push failure is `Failed`. The push is ONE call over
/// all of the user's connections; the remote-control teardown hook then runs
/// ONCE for the user, after it and outside any per-connection loop.
///
/// ORDER (S-3 B1-R): the roster flags of a user WITH voice state are
/// written before ANY SFU contact, the single-user listing included, so a
/// failed listing or push still leaves the moderator's change in Redis. The
/// table decides only what happens after that write. With the room's
/// listing failed ([`SyncConnections::Unlisted`]) the write is all there is.
/// The `UserVoiceStateUpdate` goes out only after a landed push.
#[allow(clippy::too_many_arguments)]
async fn push_user_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user: &User,
    connections: SyncConnections<'_>,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> Result<MemberSync<revolt_result::Error>> {
    let channel_id = channel.id();
    let server_id = server.as_ref().map(|s| s.id.as_str());

    let member = match server_id {
        Some(server_id) => match Reference::from_unchecked(&user.id)
            .as_member(db, server_id)
            .await
        {
            Ok(member) => Some(member),
            Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
                return Ok(MemberSync::Gone(error))
            }
            Err(error) => return Err(error),
        },
        None => None,
    };

    if role_id.is_none_or(|role_id| {
        member
            .as_ref()
            .is_none_or(|member| member.roles.iter().any(|r| r == role_id))
    }) {
        let user_voice_channel = UserVoiceChannel::from_channel(channel);

        let voice_state = get_voice_state(&user_voice_channel, &user.id).await?;

        // No state, and nothing listed or no listing to take: nothing to
        // write and nothing to push, so no permission read either.
        if voice_state.is_none()
            && matches!(
                connections,
                SyncConnections::Listed([]) | SyncConnections::Unlisted
            )
        {
            return Ok(MemberSync::Synced);
        }

        let mut query = DatabasePermissionQuery::new(db, user)
            .channel(channel)
            .user(user);

        if let (Some(server), Some(member)) = (server, member.as_ref()) {
            query = query.member(member).server(server)
        }

        let permissions = calculate_channel_permissions(&mut query).await;
        let limits = user.limits().await;

        let can_listen = permissions.has_channel_permission(ChannelPermission::Listen);
        // The AFK gate is resolved HERE, once, from the `server` this function
        // was already handed — `sync_voice_permissions` calls us once per
        // participant of the channel, so resolving it from the database per
        // participant would put an extra `fetch_server` on every member of
        // every call on every role edit. `AfkGate::resolve` uses the supplied
        // document when it is the right one and fetches only when it is not,
        // which is why the server-less callers below can still pass `None`
        // without weakening anything.
        let allowed_sources = get_allowed_sources(
            &limits,
            permissions,
            AfkGate::resolve(db, channel, server).await?,
        );

        // Audit MEDIUM-7, and the remediation of audit HIGH-1 on it. The four
        // roster flags are derived from the GATED source list, in a function
        // the regression test calls too — see `roster_flags`, which carries
        // the whole rationale (including why `recording` is not synced here).
        // Nothing may be re-typed at this call site: a copy here is exactly
        // what let the permission-bit derivation ship green once already.
        //
        // The roster flags are written BEFORE any SFU contact (S-3 B1-R).
        // Redis is the server-side truth every client renders, so a
        // moderator's server-mute, role change or timeout lands there even
        // when the listing or the push below then fails, as it did before
        // the sync became roster-driven. The event announcing the write is
        // still sent only after a landed push (below), as it always was: a
        // failed listing or push leaves the write in place and sends nothing.
        let before = roster_baseline(&user.id);
        let update_event = match &voice_state {
            Some(voice_state) => {
                let update_event = roster_flags(&user.id, &allowed_sources, voice_state);
                update_voice_state(&user_voice_channel, &user.id, &update_event).await?;
                Some(update_event)
            }
            None => None,
        };

        // The single-user entry point's own listing, the room-wide sync's
        // share of its one listing otherwise, both AFTER the write.
        let own_listing;
        let connections: &[String] = match connections {
            SyncConnections::Listed(connections) => connections,
            SyncConnections::ListRoom => {
                let listed = voice_client
                    .list_participants_reported(node, channel_id)
                    .await?
                    .unwrap_or_default();
                own_listing =
                    roster_connections(listed.into_iter().map(|participant| participant.identity))
                        .remove(&user.id)
                        .unwrap_or_default();
                &own_listing
            }
            // The room's listing failed: the flags are written, nothing is
            // pushed, and `sync_voice_permissions` answers the listing's
            // error for the room, once.
            SyncConnections::Unlisted => return Ok(MemberSync::Synced),
        };

        if connections.is_empty() {
            return Ok(match voice_state {
                None => MemberSync::Synced,
                // Voice state, but the SFU lists no connection of theirs:
                // there is no grant left to correct (F-A1).
                Some(_) => MemberSync::Gone(create_error!(InternalError)),
            });
        }

        // S-3 F-2: live at the SFU with no voice state here. The grant still
        // has to reach those connections (they would otherwise keep whatever
        // they were minted), but there is no state to correct and nothing a
        // roster renders, so nothing was written and nothing is sent.
        if update_event.is_none() {
            log::warn!(
                "permission sync of {} in {channel_id}: the SFU lists {connections:?} but \
                 there is no voice state; pushing the grant to them, writing no state",
                user.id
            );
        }

        // Every listed connection, each by its exact identity (a listed
        // screen leg gets the leg-restricted set). All of them answering
        // not_found means they have left since the listing: no grant is left
        // to correct, so the member is skipped rather than failing the sync
        // (F-A1). It stops here, before the remote-control release and the
        // fan-out.
        let pushed = voice_client
            .update_permissions_connections(
                node,
                channel_id,
                connections,
                voice_participant_permissions(can_listen, &allowed_sources),
            )
            .await?;
        if !pushed {
            return Ok(MemberSync::Gone(create_error!(InternalError)));
        }

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
        //
        // ONCE per user, after the one push over all of their connections
        // (S-3 D-4), and for a stateless live connection too: its push turned
        // data publishing off just the same.
        remote_control::release_remote_control_for_user(
            db,
            voice_client,
            &user_voice_channel,
            &user.id,
            "permissions_changed",
            false,
        )
        .await;

        if let Some(update_event) = update_event {
            if update_event != before {
                EventV1::UserVoiceStateUpdate {
                    id: user.id.clone(),
                    channel_id: channel_id.to_string(),
                    data: update_event,
                }
                .p(channel_id.to_string())
                .await;
            };
        }
    };

    Ok(MemberSync::Synced)
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

/// Remove `user_id` from every voice channel `vc:{user}` names (bots, when
/// deleted). EVERY channel is tried, with no early exit (AFK S-3 D-2): one
/// channel's failure is logged and recorded, the rest are still removed, and
/// the FIRST failure is returned once all were tried
/// ([`member_sync_result`]). Only a failed read of the channel set itself
/// returns before any removal.
pub async fn remove_user_from_voice_channels(
    db: &Database,
    voice_client: &VoiceClient,
    user_id: &str,
) -> Result<()> {
    let channels = get_user_voice_channels(user_id).await?;

    let mut outcomes = Vec::with_capacity(channels.len());
    for channel in channels {
        let removed = remove_user_from_voice_channel(db, voice_client, &channel, user_id).await;
        outcomes.push(removal_outcome(&channel.id, user_id, removed));
    }

    member_sync_result(outcomes)
}

/// Remove `user_id` from `server`'s calls (kick, ban, leaving the server;
/// AFK S-3 D-2). NOT through the single `{user}:{server}` pointer, which
/// names one channel at most: every id in `server.channels` that has a
/// LiveKit node pinned (a call is running there) goes through
/// [`remove_user_from_voice_channel`]. That reaches a user in a call they
/// hold no voice state in (a bot, a join that lost the webhook race, a
/// missed webhook) and a user who is not, or no longer, a member (the SFU
/// is asked, not the member list). The channel with no call is skipped.
///
/// The channel the pointer names is ALSO torn down, even with no node pinned
/// (a ghost left after its call ended), through the same function (its
/// no-node branch), never a whole-user `delete_voice_state`. The pointer is
/// read FIRST, because the walk's own teardowns delete it. A channel is
/// never processed twice.
///
/// No early exit: every channel is tried, a failure is logged and recorded,
/// and the FIRST failure is returned after all ([`member_sync_result`]).
pub async fn remove_user_from_server_voice(
    db: &Database,
    voice_client: &VoiceClient,
    server: &Server,
    user_id: &str,
) -> Result<()> {
    let mut outcomes = Vec::with_capacity(server.channels.len() + 2);

    let pointed = match get_user_voice_channel_in_server(user_id, &server.id).await {
        Ok(pointed) => pointed,
        Err(error) => {
            outcomes.push(removal_outcome(&server.id, user_id, Err(error)));
            None
        }
    };

    let mut removed_from = Vec::with_capacity(server.channels.len());
    for channel_id in &server.channels {
        match get_channel_node(channel_id).await {
            Ok(Some(_)) => {}
            Ok(None) => continue,
            Err(error) => {
                outcomes.push(removal_outcome(channel_id, user_id, Err(error)));
                continue;
            }
        }

        let channel = UserVoiceChannel {
            id: channel_id.clone(),
            server_id: Some(server.id.clone()),
        };
        let removed = remove_user_from_voice_channel(db, voice_client, &channel, user_id).await;
        outcomes.push(removal_outcome(channel_id, user_id, removed));
        removed_from.push(channel_id.as_str());
    }

    if let Some(channel_id) = pointed.filter(|id| !removed_from.contains(&id.as_str())) {
        let channel = UserVoiceChannel {
            id: channel_id,
            server_id: Some(server.id.clone()),
        };
        let removed = remove_user_from_voice_channel(db, voice_client, &channel, user_id).await;
        outcomes.push(removal_outcome(&channel.id, user_id, removed));
    }

    member_sync_result(outcomes)
}

/// One channel's removal, recorded for [`member_sync_result`] by the
/// removal walks, which never exit early. A failure is logged here; it has
/// already been reported where it happened.
fn removal_outcome(
    channel_id: &str,
    user_id: &str,
    removed: Result<()>,
) -> MemberSync<revolt_result::Error> {
    match removed {
        Ok(()) => MemberSync::Synced,
        Err(error) => {
            log::warn!(
                "voice removal of {user_id}: failed in {channel_id}, the remaining channels are \
                 still tried: {error:?}"
            );
            MemberSync::Failed(error)
        }
    }
}

/// Whether Redis holds ANY voice state of `user_id` tied to `channel`
/// besides the connection record: membership of `vc_members:{channel}`,
/// `channel` in `vc:{user}`, or the per-server pointer naming `channel`.
/// One pipelined read. [`remove_user_from_voice_channel`] runs nothing for a
/// user with none of these, no record and no listed connection, and the
/// moderator disconnect (`member_edit`) makes the same skip through this
/// same check (AFK S-3 WB-6).
///
/// The pointer is only ever COMPARED with `channel` here, never used to pick
/// a channel: a caller that must act on one particular channel (the
/// disconnect's gated source) stays on it.
pub async fn holds_voice_state_in(channel: &UserVoiceChannel, user_id: &str) -> Result<bool> {
    let parent = channel.server_id.as_ref().unwrap_or(&channel.id);

    let (member, listed, pointer): (bool, bool, Option<String>) = Pipeline::new()
        .sismember(format!("vc_members:{}", &channel.id), user_id)
        .sismember(format!("vc:{user_id}"), channel)
        .get(format!("{user_id}:{parent}"))
        .query_async(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()?;

    Ok(member || listed || pointer.as_deref() == Some(channel.id.as_str()))
}

/// The connection records a removal may delete: every sid the eviction
/// returned (the user's primaries in its ONE listing), then every sid
/// `recorded` BEFORE that listing that the SFU did not list (stale), each
/// once. `evicted` is `None` when there was no listing to evict from (no
/// node pinned, or the SFU has no such room): the recorded sids alone.
/// Pure. Shared by every removal that decides from a listing: this crate's
/// [`tear_down_removed_connections`] and `voice_join`'s force-disconnect
/// (AFK S-3 WB-6), so the union cannot drift between them.
pub fn removal_teardown_sids(evicted: Option<Vec<String>>, recorded: Vec<String>) -> Vec<String> {
    let mut sids = evicted.unwrap_or_default();
    for sid in recorded {
        if !sids.contains(&sid) {
            sids.push(sid);
        }
    }
    sids
}

/// Whether a removal's teardown must publish the `VoiceChannelLeave` itself
/// (AFK S-3 WB-8): exactly when it removed the user's LAST connection or
/// state here (`Last`) and no SFU webhook will announce the departure.
///
/// A primary the removal evicted leaves the room, and its
/// `participant_left` publishes the Leave from voice-ingress on `Last` (the
/// record the teardown already deleted reads as no survivor there). With no
/// primary evicted (no node pinned, a room the SFU no longer has, or a
/// listing that named nothing of the user) nothing will ever leave the SFU,
/// so no webhook follows, and without this every other client kept the
/// ghost on its roster. Never on `Survivor`: the user is still in the call.
/// Pure.
fn removal_publishes_leave(leave: ConnectionLeave, announced_by_webhook: bool) -> bool {
    leave == ConnectionLeave::Last && !announced_by_webhook
}

/// The teardown of a removal that decided from a listing (AFK S-3 D-2, as
/// amended by WA-R / RA2-1): the set delete of
/// `returned ∪ (recorded − returned)` ([`removal_teardown_sids`]), never the
/// whole-user [`delete_voice_state`], then the `VoiceChannelLeave` when
/// [`removal_publishes_leave`] says no webhook will announce it (WB-8).
///
/// `evicted` is what `remove_user_if_present_sids` returned (`None` with no
/// listing), `recorded` the sids read BEFORE that listing.
///
/// A caller MUST read `recorded` ([`recorded_voice_connections`]) before
/// it lists the room, never after (the WA-R ordering rule). Read after, a
/// sibling that records between the listing and the read is in `recorded`
/// but not in `evicted`, so it reads as stale and its record, and the state
/// it keeps alive, is deleted while it is live: S-3 WA-1. Nothing here can
/// check that, so the callers are an allowlist
/// (`the_set_teardown_callers_are_exactly_the_record_first_ones`), each
/// with its order pinned at its own site: [`remove_user_from_voice_channel`],
/// the moderator disconnect in `member_edit`, and the force-disconnect in
/// `voice_join` (AFK S-3 WC-3). The caller has already decided the user
/// holds something here, or that the listing named them.
pub async fn tear_down_removed_connections(
    channel: &UserVoiceChannel,
    user_id: &str,
    evicted: Option<Vec<String>>,
    recorded: Vec<String>,
) -> Result<ConnectionLeave> {
    let announced_by_webhook = evicted.as_ref().is_some_and(|sids| !sids.is_empty());

    let leave =
        delete_voice_connections(channel, user_id, &removal_teardown_sids(evicted, recorded))
            .await?;

    if removal_publishes_leave(leave, announced_by_webhook) {
        EventV1::VoiceChannelLeave {
            id: channel.id.clone(),
            user: user_id.to_string(),
        }
        .p(channel.id.clone())
        .await;
    }

    Ok(leave)
}

/// Report a failed eviction from a call where Redis holds nothing of
/// `user_id` (AFK S-3 WB-2), which [`remove_user_from_voice_channel`] then
/// answers with `Ok(())`: one ERROR log and one Sentry event per failure,
/// plus one WARN naming the user and the skipped channel. Only an
/// [`EvictionFailure::Unlisted`] reaches it (AFK S-3 WBR-3): a `Listed` one
/// is returned as the error.
///
/// Every `InternalError` in an `Unlisted` failure has already gone through
/// `to_internal_error()` where it happened (the listing in
/// `list_participants_reported`), so it is not reported a second time here.
/// Any other error (the `UnknownNode` of a pin naming a node missing from
/// the config) was reported nowhere, and goes through `to_internal_error()`
/// here, exactly once.
fn report_unheld_eviction_failure(channel_id: &str, user_id: &str, error: revolt_result::Error) {
    log::warn!(
        "voice removal of {user_id}: the eviction from {channel_id} failed and Redis holds \
         nothing of the user there, so the channel is skipped: {error:?}"
    );
    if !matches!(error.error_type, revolt_result::ErrorType::InternalError) {
        let _ = Err::<(), _>(error).to_internal_error();
    }
}

/// Remove `user_id` from `channel`: every connection of theirs the SFU
/// lists is evicted, then EXACTLY the connection records this removal knows
/// about are deleted, in the set mode of the teardown script (AFK S-3 D-2,
/// amended by WA-R / RA2-1).
///
/// ORDERING RULE: [`recorded_voice_connections`] is read BEFORE any SFU
/// listing, never after. Read after, a sibling that records between the
/// listing and the read looks stale (recorded but not listed) and is deleted
/// while live: S-3 WA-1 again. Read before, such a sibling is in neither
/// set, so [`delete_voice_connections`]'s survivor scan keeps its state: a
/// connection recorded after that read is a legitimate new join and survives
/// with its state (kick, ban and leaving the server all remove the
/// membership first, so the join's Connect re-check refuses such joins).
///
/// This path decides from a listing, so it NEVER runs the whole-user
/// [`delete_voice_state`]; that would erase the late sibling's state.
///
/// 1. The recorded sids. A failed read returns `Err` before any eviction; it
///    is never taken for an empty set.
/// 2. Whether Redis holds any other voice state of the user here
///    ([`holds_voice_state_in`]; a failed read returns `Err` before any
///    eviction too).
/// 3. With a node pinned, `remove_user_if_present_sids`: ONE listing, every
///    listed connection evicted. No node pinned: no eviction (a ghost of a
///    call that has ended), the recorded sids alone. A failure never tears
///    anything down, and it is typed by whether the room was listed (AFK S-3
///    WBR-3, [`EvictionFailure`]):
///    - `Listed`: the SFU listed a connection of the user and removing it
///      failed. The `Err` returns whatever Redis holds: that connection may
///      still be live, and a kick or ban must not answer 200 over it. With
///      nothing in Redis the remote-control release runs first (the listing
///      is the first sign of the user, as in the skip below), actively
///      revoking.
///    - `Unlisted` (a failed listing, or a pin naming a node missing from
///      the config), with something of the user in Redis here: the `Err`
///      returns at once, so a connection that may still be live stays
///      visible and syncable, and the caller can retry.
///    - `Unlisted`, with nothing of the user in Redis here (AFK S-3 WB-2):
///      the failure is reported once ([`report_unheld_eviction_failure`])
///      and the channel answers `Ok(())`, with no release and no script. The
///      server walk sends every member of a server through every call in
///      it, after the membership is already removed (AFK S-3 S6A-1, for a
///      kick, a ban and a leave alike). A kick or ban answers the walk's
///      error; a leave reports it and discards it (its membership is gone,
///      so a retry could only answer `NotFound`). One call on a down or
///      unknown node would otherwise fail every kick and ban, and log a
///      failed eviction for every leave, in that server, for users who were
///      never in that call.
///
///    ACCEPTED RESIDUAL: a live connection the SFU has and Redis does not (a
///    join that lost the webhook race, a missed webhook) on a node that
///    cannot be listed is not evicted. Nothing could evict it while the node
///    cannot be listed anyway, and the failure is reported. (Such a
///    connection on a node that COULD be listed, whose removal failed, used
///    to share that `Ok`, because the two failures were one untyped `Err`:
///    WBR-3 made it the error.)
/// 4. `delete_voice_connections(returned ∪ (recorded − returned))`, or the
///    recorded sids for a room the SFU no longer has, through
///    [`tear_down_removed_connections`]. An EMPTY set is the script's pure
///    survivor check: with nothing of the user recorded it is `Last` and the
///    full teardown, which is what a user with state and no record (a legacy
///    connection, or a ghost) needs. A `Last` that no webhook will announce
///    (nothing evicted: a ghost of an ended call, or of a room the SFU no
///    longer has) publishes the `VoiceChannelLeave` here (AFK S-3 WB-8).
///
/// Callers: kick (`member_remove`), ban (`ban_create`) and leaving the server
/// (`server_delete`), all three through [`remove_user_from_server_voice`];
/// `channel_delete`; `group_remove_member`; bot deletion (through
/// [`remove_user_from_voice_channels`]), and voice-ingress (the
/// `participant_joined` cap backstop, when a sibling connection answers
/// `Survivor`, AFK S-3 WB-3).
///
/// SKIPPED ENTIRELY (P2-6 + RA2-1): a user with nothing recorded, no voice
/// state here (step 2) and no connection listed gets no remote-control
/// release and no script, so walking every call of a server costs one
/// listing per call, not a script per call. The skip is decided in two
/// halves so that the release still PRECEDES the eviction whenever Redis
/// shows the user here: that is known before the listing, so the release
/// runs before it. When only the SFU knows of the user (a connection with
/// no state), that is known only from the listing, which is also the
/// eviction; the release then runs right after it, before the teardown (or,
/// when a listed removal failed, before that error returns). When the
/// eviction succeeded, such a connection's capability went with it; when a
/// removal failed, it may still be live. Either way the release clears the
/// grant records and revokes actively: their controller where the user was
/// the sharer, the user's own capability where they were a controller.
pub async fn remove_user_from_voice_channel(
    db: &Database,
    voice_client: &VoiceClient,
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    let recorded: Vec<String> = recorded_voice_connections(channel, user_id)
        .await?
        .into_iter()
        .map(|(sid, _)| sid)
        .collect();
    let holds_state = !recorded.is_empty() || holds_voice_state_in(channel, user_id).await?;

    // Remote-control release hook (plan §1): these admin paths remove the
    // participant INSIDE delta and would race a webhook-only hook, so any
    // grant involving this user is ended here, before the removal.
    //
    // `false`: the eviction below can fail (and then nothing is torn down),
    // so assuming it works and merely deleting the records would be how a
    // `can_publish_data` capability outlives everything able to revoke it:
    // the capability is actively revoked first.
    if holds_state {
        remote_control::release_remote_control_for_user(
            db,
            voice_client,
            channel,
            user_id,
            "participant_left",
            false,
        )
        .await;
    }

    let evicted = match get_channel_node(&channel.id).await? {
        Some(node) => match voice_client
            .remove_user_if_present_sids(&node, user_id, &channel.id)
            .await
        {
            Ok(evicted) => evicted,
            // WBR-3: the SFU LISTED a connection of the user and removing it
            // failed. It may still be live, whatever Redis holds: nothing is
            // torn down and the error is the answer. With nothing in Redis
            // the release above did not run, and the listing is the first
            // this removal knows of the user, so it runs now, actively
            // revoking, before the error returns.
            Err(EvictionFailure::Listed(error)) => {
                if !holds_state {
                    remote_control::release_remote_control_for_user(
                        db,
                        voice_client,
                        channel,
                        user_id,
                        "participant_left",
                        false,
                    )
                    .await;
                }
                return Err(error);
            }
            // Never listed, and Redis holds something of the user here: a
            // connection that may still be live, so nothing is torn down.
            Err(EvictionFailure::Unlisted(error)) if holds_state => return Err(error),
            // WB-2: never listed, and Redis holds nothing of the user here to
            // tear down.
            Err(EvictionFailure::Unlisted(error)) => {
                report_unheld_eviction_failure(&channel.id, user_id, error);
                return Ok(());
            }
        },
        None => None,
    };

    if !holds_state {
        if evicted.as_ref().is_none_or(Vec::is_empty) {
            // Nothing of the user here at all: no release, no script.
            return Ok(());
        }
        // Known only from the listing: a live connection with no state.
        remote_control::release_remote_control_for_user(
            db,
            voice_client,
            channel,
            user_id,
            "participant_left",
            false,
        )
        .await;
    }

    tear_down_removed_connections(channel, user_id, evicted, recorded).await?;

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
    ///
    /// Visible to the sibling test modules because a test that only touches
    /// Redis INDIRECTLY (the event publishes inside `Server::create`,
    /// `Channel::create_server_channel` and `Server::update`) poisons the pool
    /// just the same when Redis is up. AFK Stage 6's database-backed tests run
    /// here for that reason: as `#[tokio::test]`s they failed a Redis test in
    /// 2 of 5 full runs, and 0 of 8 without them.
    pub(super) fn rt() -> &'static tokio::runtime::Runtime {
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

    // The `watching` roster flag (watch-together plan §7.3, 4b): created
    // false with the voice state, set/cleared through the partial-update
    // path, gone with the state — and a state written before the key existed
    // still reads (the additive-key rule, `get_voice_state`'s non-required
    // tuple).
    #[test]
    fn watching_flag_lifecycle() {
        rt().block_on(watching_flag_case())
    }

    async fn watching_flag_case() {
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
        assert!(!state.watching, "a fresh join never inherits the flag");

        update_voice_state(
            &channel,
            &user,
            &v0::PartialUserVoiceState {
                watching: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(state.watching);

        // An absent additive key must read false, never drop the state
        // (states created before the key existed).
        let mut conn = get_connection().await.unwrap();
        let _: () = conn
            .del(format!("watching:{user}:srv{suffix}"))
            .await
            .unwrap();
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(!state.watching, "absent key reads false, not a dropped state");

        delete_voice_state(&channel, &user).await.expect("cleanup");
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
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

    // The screen-leg marker (`vc_leg:{channel}`) and the two leave guards
    // (android-screen-share plan §2.3). There is no voice-ingress test infra
    // (zero `#[cfg(test)]`, `VoiceClient` wraps a concrete `RoomClient` with
    // no trait to fake), so this is where the leg's state logic is actually
    // proven; the SFU-side removals are covered only by the live leg §10.1.
    //
    // The ORDER of the guards is the whole point: the voice-state guard must
    // run BEFORE any write, or a leg leaving after its owner resurrects
    // TTL-less `screensharing:` / `screen_video:` keys nothing will ever clean
    // up, plus a spurious update event for a departed user (§0-R.13).
    #[test]
    fn screen_leg_marker_lifecycle_and_leave_guards() {
        rt().block_on(screen_leg_marker_case())
    }

    async fn screen_leg_marker_case() {
        let suffix = ulid::Ulid::new().to_string();
        let channel = UserVoiceChannel {
            id: format!("chan{suffix}"),
            server_id: Some(format!("srv{suffix}")),
        };
        let user = format!("user{suffix}");
        let unique_key = format!("{user}:srv{suffix}");

        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .expect("seed voice state");

        // The leg joins and publishes: the marker is the leg's, the FLAGS are
        // the owner's — a leg never gets voice state of its own.
        record_screen_leg(&channel.id, &user, "SID_ONE").await.unwrap();
        update_voice_state_tracks(&channel, &user, true, 3)
            .await
            .unwrap();
        assert_eq!(
            get_screen_leg_sid(&channel.id, &user)
                .await
                .unwrap()
                .as_deref(),
            Some("SID_ONE")
        );

        // Sid guard: a leave from a participant the marker no longer names is
        // an OLDER leg that a re-share already replaced (the SFU evicts the
        // earlier connection on a same-identity join). Acting on it would
        // blank the live share's badge.
        assert!(screen_leg_left(&channel, &user, "SID_ZERO")
            .await
            .unwrap()
            .is_none());
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(
            state.screen_video,
            "a superseded leg's late leave must not clear a live share"
        );
        assert_eq!(
            get_screen_leg_sid(&channel.id, &user)
                .await
                .unwrap()
                .as_deref(),
            Some("SID_ONE"),
            "...nor drop the live leg's marker"
        );

        // The real leave clears BOTH flags, drops the marker, and hands back
        // the delta to announce (LiveKit does not reliably send
        // track_unpublished for a participant that vanished).
        let partial = screen_leg_left(&channel, &user, "SID_ONE")
            .await
            .unwrap()
            .expect("the owning leg's leave must yield a voice-state delta");
        assert_eq!(partial.screensharing, Some(false));
        assert_eq!(partial.screen_video, Some(false));
        let state = get_voice_state(&channel, &user).await.unwrap().unwrap();
        assert!(!state.screensharing);
        assert!(!state.screen_video);
        assert!(get_screen_leg_sid(&channel.id, &user)
            .await
            .unwrap()
            .is_none());

        // Idempotent: a duplicate delivery finds no marker and does nothing.
        assert!(screen_leg_left(&channel, &user, "SID_ONE")
            .await
            .unwrap()
            .is_none());

        // `delete_voice_state` is the chokepoint every leave / reconcile path
        // shares, and the marker hash has NO TTL — a field it failed to clean
        // would outlive the call forever.
        record_screen_leg(&channel.id, &user, "SID_TWO").await.unwrap();
        delete_voice_state(&channel, &user).await.expect("leave");
        assert!(get_screen_leg_sid(&channel.id, &user)
            .await
            .unwrap()
            .is_none());

        // Owner gone, and a marker deliberately re-seeded so the SID guard
        // alone would let this through: the voice-state guard must fire first
        // and write nothing at all.
        record_screen_leg(&channel.id, &user, "SID_THREE")
            .await
            .unwrap();
        assert!(screen_leg_left(&channel, &user, "SID_THREE")
            .await
            .unwrap()
            .is_none());

        let mut conn = get_connection().await.unwrap();
        let (screensharing, screen_video): (Option<bool>, Option<bool>) = conn
            .mget(&[
                format!("screensharing:{unique_key}"),
                format!("screen_video:{unique_key}"),
            ])
            .await
            .unwrap();
        assert!(
            screensharing.is_none() && screen_video.is_none(),
            "a leg leaving after its owner must not resurrect TTL-less voice-state keys"
        );

        // `delete_channel_voice_state` (room_finished / reconcile_channel,
        // which pass no user ids) drops the whole per-channel hash.
        delete_channel_voice_state(&channel, &[user.clone()])
            .await
            .expect("cleanup");
        let leg_hash_exists: bool = conn
            .exists(format!("vc_leg:{}", &channel.id))
            .await
            .unwrap();
        assert!(
            !leg_hash_exists,
            "the per-channel leg hash must not outlive the call"
        );
    }

    // H-1 (AFK Wave 5b-1). COMPILE-ONLY ON A BOX WITHOUT REDIS, OWED TO CI:
    // like the other Redis-backed tests here it fails at its first
    // `get_connection` with `InternalError` when no server is reachable.
    //
    // `delete_voice_state` keeps the per-server pointer and flags when the
    // pointer names a DIFFERENT channel (a late leave from the source after
    // the destination's join), and deletes them when it names this channel
    // or nothing. Per-channel state (`vc_members`, the `vc:` entry, the
    // `vc_leg` and `voice_identity` fields, `annotations_allow`) goes in
    // every case, and another channel's per-channel state is never touched.
    #[test]
    fn delete_voice_state_keeps_per_server_state_after_a_move() {
        rt().block_on(delete_voice_state_after_a_move_case())
    }

    /// Give `user` a value in every per-channel key the teardown script
    /// clears, beyond the two `create_voice_state` already writes — including
    /// two entries in the connection record (S-3 D-1), which the whole-user
    /// teardown must clear both of.
    async fn seed_per_channel_voice_state(conn: &mut Conn, channel: &UserVoiceChannel, user: &str) {
        let _: () = conn
            .hset(format!("vc_leg:{}", channel.id), user, "SID")
            .await
            .unwrap();
        for (sid, identity) in [("CONN_A", user.to_string()), ("CONN_B", format!("{user}:D1"))] {
            let _: () = conn
                .hset(format!("vc_conns:{}", channel.id), format!("{sid}{user}"), identity)
                .await
                .unwrap();
        }
        let _: () = conn
            .hset(
                format!("voice_identity:{}", channel.id),
                user,
                format!("{user}:D1"),
            )
            .await
            .unwrap();
        let _: () = conn
            .sadd(
                format!("annotations_allow:{}:{user}", channel.id),
                "ANNOTATOR",
            )
            .await
            .unwrap();
    }

    /// Every per-channel key of `user` in `channel` is gone.
    async fn assert_per_channel_voice_state_gone(
        conn: &mut Conn,
        channel: &UserVoiceChannel,
        user: &str,
        case: &str,
    ) {
        let member: bool = conn
            .sismember(format!("vc_members:{}", channel.id), user)
            .await
            .unwrap();
        let listed: bool = conn.sismember(format!("vc:{user}"), channel).await.unwrap();
        let leg: bool = conn
            .hexists(format!("vc_leg:{}", channel.id), user)
            .await
            .unwrap();
        let identity: bool = conn
            .hexists(format!("voice_identity:{}", channel.id), user)
            .await
            .unwrap();
        let annotations: bool = conn
            .exists(format!("annotations_allow:{}:{user}", channel.id))
            .await
            .unwrap();
        let connections: std::collections::BTreeMap<String, String> = conn
            .hgetall(format!("vc_conns:{}", channel.id))
            .await
            .unwrap();
        let recorded = connections
            .values()
            .any(|recorded| user_id_from_participant_identity(recorded) == user);

        assert_eq!(
            (member, listed, leg, identity, annotations, recorded),
            (false, false, false, false, false, false),
            "{case}: per-channel state must go unconditionally \
             (vc_members, vc:, vc_leg, voice_identity, annotations_allow, and \
             every vc_conns entry of the user)"
        );
    }

    async fn delete_voice_state_after_a_move_case() {
        let suffix = ulid::Ulid::new().to_string();
        let server = format!("srv{suffix}");
        let source = UserVoiceChannel {
            id: format!("chanA{suffix}"),
            server_id: Some(server.clone()),
        };
        let destination = UserVoiceChannel {
            id: format!("chanB{suffix}"),
            server_id: Some(server.clone()),
        };
        let user = format!("user{suffix}");
        let unique_key = format!("{user}:{server}");
        let flag_keys: Vec<String> = [
            "joined_at",
            "is_publishing",
            "is_receiving",
            "screensharing",
            "camera",
            "screen_video",
            "recording",
            "rc_capable",
            "watching",
        ]
        .iter()
        .map(|flag| format!("{flag}:{unique_key}"))
        .collect();

        let mut conn = get_connection().await.expect("redis");

        // Case 1 — the pointer names ANOTHER channel. The user joined the
        // source, then the destination (pointer -> destination, flags are the
        // destination's), and the source's leave lands late.
        create_voice_state(&source, &user, Timestamp::now_utc())
            .await
            .expect("seed source");
        create_voice_state(&destination, &user, Timestamp::now_utc())
            .await
            .expect("seed destination");
        update_voice_state_tracks(&destination, &user, true, 2)
            .await
            .unwrap();
        seed_per_channel_voice_state(&mut conn, &source, &user).await;
        seed_per_channel_voice_state(&mut conn, &destination, &user).await;

        delete_voice_state(&source, &user)
            .await
            .expect("late leave");
        assert_per_channel_voice_state_gone(&mut conn, &source, &user, "pointer elsewhere").await;
        let still_in_destination: bool = conn
            .sismember(format!("vc_members:{}", destination.id), &user)
            .await
            .unwrap();
        let destination_identity: bool = conn
            .hexists(format!("voice_identity:{}", destination.id), &user)
            .await
            .unwrap();
        let destination_connections: u64 = conn
            .hlen(format!("vc_conns:{}", destination.id))
            .await
            .unwrap();
        assert!(
            still_in_destination && destination_identity && destination_connections == 2,
            "a leave from the source must not touch the destination's per-channel state \
             (connection record included)"
        );

        let pointer: Option<String> = conn.get(&unique_key).await.unwrap();
        assert_eq!(
            pointer.as_deref(),
            Some(destination.id.as_str()),
            "a late leave from the source must not clear the destination's pointer"
        );
        let state = get_voice_state(&destination, &user)
            .await
            .unwrap()
            .expect("the destination's voice state must survive a late source leave");
        assert!(state.is_publishing, "...flags included");
        let in_source: bool = conn
            .sismember(format!("vc_members:{}", source.id), &user)
            .await
            .unwrap();
        assert!(
            !in_source,
            "per-channel membership of the source still goes"
        );
        let channels = get_user_voice_channels(&user).await.unwrap();
        assert!(
            channels.iter().all(|channel| channel.id != source.id),
            "the source leaves vc:{{user}} unconditionally"
        );

        // Case 2 — the pointer names THIS channel: everything goes.
        delete_voice_state(&destination, &user)
            .await
            .expect("leave");
        assert_per_channel_voice_state_gone(&mut conn, &destination, &user, "pointer here").await;
        let pointer: Option<String> = conn.get(&unique_key).await.unwrap();
        assert_eq!(pointer, None);
        let flags: Vec<Option<String>> = conn.mget(&flag_keys).await.unwrap();
        assert!(
            flags.iter().all(Option::is_none),
            "a leave from the channel the pointer names clears every flag: {flags:?}"
        );

        // Case 3 — no pointer at all: the flags are orphans and go.
        create_voice_state(&source, &user, Timestamp::now_utc())
            .await
            .expect("reseed");
        seed_per_channel_voice_state(&mut conn, &source, &user).await;
        let _: () = conn.del(&unique_key).await.unwrap();
        delete_voice_state(&source, &user).await.expect("leave");
        assert_per_channel_voice_state_gone(&mut conn, &source, &user, "no pointer").await;
        let flags: Vec<Option<String>> = conn.mget(&flag_keys).await.unwrap();
        assert!(
            flags.iter().all(Option::is_none),
            "a nil pointer must delete, never keep: {flags:?}"
        );
    }

    // AFK idle claims (Wave 5b-2). COMPILE-ONLY ON A BOX WITHOUT REDIS, OWED
    // TO CI: like the other Redis-backed tests here it fails at its first
    // `get_connection` with `InternalError` when no server is reachable.
    //
    // The claim's whole Redis life: created with a TTL and an index entry,
    // refreshed without moving `since`, replaced for another channel, read
    // back through `read_idle_state` against a real voice state, requeued
    // (XX) and cleared, withdrawn under a tombstone that stops the next PUT
    // until it is gone (N-4), refused when it claims more idle time than
    // the call has lasted (F-A2), and deleted by the next join.
    //
    // The seed join is backdated ten minutes: a claim of 120 s against a
    // join stamped "now" is exactly what F-A2 refuses.
    #[test]
    fn afk_idle_claim_lifecycle() {
        rt().block_on(afk_idle_claim_lifecycle_case())
    }

    /// The member's score in the AFK idle index, if it has one.
    async fn afk_idle_score(conn: &mut Conn, member: &str) -> Option<i64> {
        let score: Option<f64> = conn
            .zscore(afk_idle::AFK_IDLE_INDEX_KEY, member)
            .await
            .unwrap();
        score.map(|score| score as i64)
    }

    async fn afk_idle_claim_lifecycle_case() {
        use afk_idle::*;

        let suffix = ulid::Ulid::new().to_string();
        let server = format!("srv{suffix}");
        let channel = UserVoiceChannel {
            id: format!("chanA{suffix}"),
            server_id: Some(server.clone()),
        };
        let other = format!("chanB{suffix}");
        let user = format!("user{suffix}");
        let member = afk_idle_member(&user, &server);
        let mut conn = get_connection().await.expect("redis");

        let ten_minutes_ago = Timestamp::now_utc()
            .checked_sub(Duration::minutes(10))
            .expect("a timestamp ten minutes ago");
        create_voice_state(&channel, &user, ten_minutes_ago)
            .await
            .expect("seed voice state");
        let state = read_idle_state(&user, &server).await.unwrap();
        assert_eq!(state.claim, None);
        assert_eq!(state.pointer.as_deref(), Some(channel.id.as_str()));
        assert!(state.joined_at_ms.is_some());
        assert!(!state.screensharing && !state.camera && !state.recording);

        // Create: SET NX EX, and an index entry one minute after `since`.
        set_afk_since(&user, &server, &channel.id, 120)
            .await
            .unwrap();
        let created = get_afk_since(&user, &server).await.unwrap().expect("claim");
        assert_eq!(created.channel_id, channel.id);
        assert!(
            created.since_ms >= state.joined_at_ms.unwrap(),
            "clamped to the join"
        );
        let ttl: i64 = conn.ttl(afk_since_key(&user, &server)).await.unwrap();
        assert!(ttl > 0 && ttl <= AFK_SINCE_TTL_SECS as i64, "ttl {ttl}");
        assert_eq!(
            afk_idle_score(&mut conn, &member).await,
            Some(created.since_ms + 60_000)
        );

        // Refresh: same channel, `since` does not move, nor does the score.
        set_afk_since(&user, &server, &channel.id, 0).await.unwrap();
        assert_eq!(
            get_afk_since(&user, &server).await.unwrap(),
            Some(created.clone())
        );
        assert_eq!(
            afk_idle_score(&mut conn, &member).await,
            Some(created.since_ms + 60_000)
        );

        // Replace: another channel, a fresh claim; the index keeps its score.
        set_afk_since(&user, &server, &other, 0).await.unwrap();
        let replaced = get_afk_since(&user, &server).await.unwrap().expect("claim");
        assert_eq!(replaced.channel_id, other);
        assert!(replaced.since_ms >= created.since_ms);

        // The sweep's view, and its index operations.
        assert!(due_idle_members(created.since_ms + 60_000, 100_000)
            .await
            .unwrap()
            .contains(&member));
        requeue_idle_member(&member, 42).await.unwrap();
        assert_eq!(afk_idle_score(&mut conn, &member).await, Some(42));
        drop_idle_member(&member).await.unwrap();
        requeue_idle_member(&member, 43).await.unwrap();
        assert_eq!(
            afk_idle_score(&mut conn, &member).await,
            None,
            "XX never re-creates"
        );

        // Clear: the key and the index entry.
        set_afk_since(&user, &server, &channel.id, 0).await.unwrap();
        clear_afk_since(&user, &server).await.unwrap();
        assert_eq!(get_afk_since(&user, &server).await.unwrap(), None);
        assert_eq!(afk_idle_score(&mut conn, &member).await, None);

        // N-4 — the withdrawal: the claim and its entry go, and a tombstone
        // stands for at most AFK_IDLE_TOMB_TTL_SECS.
        set_afk_since(&user, &server, &channel.id, 120)
            .await
            .unwrap();
        assert!(get_afk_since(&user, &server).await.unwrap().is_some());
        withdraw_afk_since(&user, &server).await.unwrap();
        assert_eq!(get_afk_since(&user, &server).await.unwrap(), None);
        assert_eq!(afk_idle_score(&mut conn, &member).await, None);
        let tomb_ttl: i64 = conn.ttl(afk_idle_tomb_key(&user, &server)).await.unwrap();
        assert!(
            tomb_ttl > 0 && tomb_ttl <= AFK_IDLE_TOMB_TTL_SECS as i64,
            "tomb ttl {tomb_ttl}"
        );

        // While it stands, a PUT succeeds and writes nothing: no claim, no
        // index entry.
        set_afk_since(&user, &server, &channel.id, 120)
            .await
            .unwrap();
        assert_eq!(
            get_afk_since(&user, &server).await.unwrap(),
            None,
            "a PUT under a tombstone writes nothing"
        );
        assert_eq!(afk_idle_score(&mut conn, &member).await, None);

        // The tomb's expiry (deleted here rather than waited out) lets the
        // next PUT write again.
        let _: () = conn.del(afk_idle_tomb_key(&user, &server)).await.unwrap();
        set_afk_since(&user, &server, &channel.id, 120)
            .await
            .unwrap();
        assert!(
            get_afk_since(&user, &server).await.unwrap().is_some(),
            "with the tombstone gone the PUT writes again"
        );
        assert!(afk_idle_score(&mut conn, &member).await.is_some());
        clear_afk_since(&user, &server).await.unwrap();

        // A join deletes the claim (I-2).
        set_afk_since(&user, &server, &channel.id, 0).await.unwrap();
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .expect("rejoin");
        assert_eq!(get_afk_since(&user, &server).await.unwrap(), None);

        // F-A2 — a claim of 120 s against a join stamped now (a stale
        // refresh from before the rejoin) writes nothing; an honest one does.
        // The join deletes the claim but not its index entry (the sweep
        // drops that), so it is dropped here first to observe "no ZADD".
        drop_idle_member(&member).await.unwrap();
        set_afk_since(&user, &server, &channel.id, 120)
            .await
            .unwrap();
        assert_eq!(
            get_afk_since(&user, &server).await.unwrap(),
            None,
            "a claim idle for longer than the call writes nothing"
        );
        assert_eq!(afk_idle_score(&mut conn, &member).await, None);
        set_afk_since(&user, &server, &channel.id, 0).await.unwrap();
        assert!(get_afk_since(&user, &server).await.unwrap().is_some());

        clear_afk_since(&user, &server).await.unwrap();
        drop_idle_member(&member).await.unwrap();
        delete_voice_state(&channel, &user).await.expect("cleanup");
    }

    // ---- the per-connection record (AFK S-3 D-1) ----
    //
    // Every case below drives the REAL functions against Redis on the shared
    // runtime, with ULID-suffixed ids, and leaves nothing behind.

    /// A fresh server voice channel and user id for one case.
    fn connection_case_ids(tag: &str) -> (UserVoiceChannel, String, String) {
        let suffix = ulid::Ulid::new().to_string();
        let server = format!("srv{tag}{suffix}");
        (
            UserVoiceChannel {
                id: format!("chan{tag}{suffix}"),
                server_id: Some(server.clone()),
            },
            format!("user{tag}{suffix}"),
            server,
        )
    }

    async fn recorded_connections(
        conn: &mut Conn,
        channel: &UserVoiceChannel,
    ) -> std::collections::BTreeMap<String, String> {
        conn.hgetall(format!("vc_conns:{}", channel.id))
            .await
            .unwrap()
    }

    async fn is_voice_member(conn: &mut Conn, channel: &UserVoiceChannel, user: &str) -> bool {
        conn.sismember(format!("vc_members:{}", channel.id), user)
            .await
            .unwrap()
    }

    /// Every per-server key of `user` under `server`: the pointer and the
    /// nine flags.
    fn per_server_keys(user: &str, server: &str) -> Vec<String> {
        let unique_key = format!("{user}:{server}");
        let mut keys: Vec<String> = [
            "joined_at",
            "is_publishing",
            "is_receiving",
            "screensharing",
            "camera",
            "screen_video",
            "recording",
            "rc_capable",
            "watching",
        ]
        .iter()
        .map(|flag| format!("{flag}:{unique_key}"))
        .collect();
        keys.push(unique_key);
        keys
    }

    /// T1 + F-15: two connections of one user in one channel. The second
    /// join does not reset the state; the first leave keeps the state, the
    /// membership and the flags and re-points the mapping at the survivor;
    /// the second leave tears everything down. Mutation n1 (the script's
    /// survivor branch removed) turns the first leave into a teardown.
    #[test]
    fn a_surviving_connection_keeps_the_voice_state() {
        rt().block_on(a_surviving_connection_keeps_the_voice_state_case())
    }

    async fn a_surviving_connection_keeps_the_voice_state_case() {
        let (channel, user, server) = connection_case_ids("T1");
        let (first, second) = (format!("{user}:D1"), format!("{user}:D2"));
        let mut conn = get_connection().await.expect("redis");

        assert!(
            record_voice_connection(&channel, &user, "SID1", &first)
                .await
                .unwrap(),
            "the first connection has no voice state yet"
        );
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_voice_participant_identity(&channel.id, &user, &first)
            .await
            .unwrap();
        assert!(
            !record_voice_connection(&channel, &user, "SID2", &second)
                .await
                .unwrap(),
            "the second connection joins a user who already holds state: no reset (F-15)"
        );
        update_voice_state(
            &channel,
            &user,
            &PartialUserVoiceState {
                camera: Some(true),
                recording: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(
            delete_voice_connection(&channel, &user, "SID1")
                .await
                .unwrap(),
            ConnectionLeave::Survivor
        );
        let state = get_voice_state(&channel, &user)
            .await
            .unwrap()
            .expect("the surviving connection keeps the voice state");
        assert!(state.camera && state.recording, "...flags included");
        assert!(is_voice_member(&mut conn, &channel, &user).await);
        assert!(get_user_voice_channels(&user).await.unwrap().contains(&channel));
        assert_eq!(
            stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap(),
            Some(second.clone()),
            "the mapping is re-pointed at the surviving connection"
        );
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID2".to_string(), second.clone())].into_iter().collect()
        );

        assert_eq!(
            delete_voice_connection(&channel, &user, "SID2")
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &channel, &user).await);
        assert!(!get_user_voice_channels(&user).await.unwrap().contains(&channel));
        assert_eq!(
            stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap(),
            None
        );
        let record_exists: bool = conn
            .exists(format!("vc_conns:{}", channel.id))
            .await
            .unwrap();
        assert!(!record_exists, "the last connection's entry is gone");
        let left: Vec<Option<String>> = conn.mget(per_server_keys(&user, &server)).await.unwrap();
        assert!(left.iter().all(Option::is_none), "{left:?}");
    }

    /// T2, the ownership rule, and the legacy path. An unknown sid while a
    /// connection of the user is recorded tears nothing down. A connection of
    /// ANOTHER user whose id merely extends this one's is not a survivor.
    /// A user the record has never seen (connected before it existed) leaves
    /// with today's teardown.
    #[test]
    fn an_unknown_sid_keeps_and_a_lookalike_user_does_not() {
        rt().block_on(an_unknown_sid_keeps_and_a_lookalike_user_does_not_case())
    }

    async fn an_unknown_sid_keeps_and_a_lookalike_user_does_not_case() {
        let (channel, user, _) = connection_case_ids("T2");
        let lookalike = format!("{user}X");
        let legacy = format!("{user}L");
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&channel, &user, "SIDA", &user)
            .await
            .unwrap());
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();

        assert_eq!(
            delete_voice_connection(&channel, &user, "SID_UNKNOWN")
                .await
                .unwrap(),
            ConnectionLeave::Survivor,
            "an unknown sid must not tear down a recorded, live connection"
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());
        assert!(recorded_connections(&mut conn, &channel)
            .await
            .contains_key("SIDA"));

        let lookalike_identity = format!("{lookalike}:D");
        assert!(
            record_voice_connection(&channel, &lookalike, "SIDX", &lookalike_identity)
                .await
                .unwrap()
        );
        assert_eq!(
            delete_voice_connection(&channel, &user, "SIDA")
                .await
                .unwrap(),
            ConnectionLeave::Last,
            "`{{user}}X:D` is another user's connection, not a survivor of `{{user}}`"
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SIDX".to_string(), lookalike_identity)]
                .into_iter()
                .collect(),
            "only the leaving user's entries go"
        );

        create_voice_state(&channel, &legacy, Timestamp::now_utc())
            .await
            .unwrap();
        assert_eq!(
            delete_voice_connection(&channel, &legacy, "SID_LEGACY")
                .await
                .unwrap(),
            ConnectionLeave::Last,
            "no record at all is a last connection, as before S-3"
        );
        assert!(get_voice_state(&channel, &legacy).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &channel, &legacy).await);

        delete_channel_voice_state(&channel, &[lookalike])
            .await
            .expect("cleanup");
    }

    /// T-late: a connection keeps its identity across a move. The late
    /// `participant_left` of its SOURCE connection is the source's last,
    /// tears the source down, and leaves the destination's record, membership
    /// and state alone. Mutation n5 (the record keyed per server): the source
    /// leave finds the destination entry, answers `Survivor` and keeps the
    /// source state.
    #[test]
    fn a_late_source_leave_leaves_the_destination_alone() {
        rt().block_on(a_late_source_leave_leaves_the_destination_alone_case())
    }

    async fn a_late_source_leave_leaves_the_destination_alone_case() {
        let (source, user, server) = connection_case_ids("TL");
        let destination = UserVoiceChannel {
            id: format!("{}D", source.id),
            server_id: Some(server),
        };
        let identity = format!("{user}:D1");
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&source, &user, "SID_S", &identity)
            .await
            .unwrap());
        create_voice_state(&source, &user, Timestamp::now_utc())
            .await
            .unwrap();
        assert!(
            record_voice_connection(&destination, &user, "SID_D", &identity)
                .await
                .unwrap(),
            "the moved connection has no state in the destination yet"
        );
        create_voice_state(&destination, &user, Timestamp::now_utc())
            .await
            .unwrap();

        assert_eq!(
            delete_voice_connection(&source, &user, "SID_S")
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(!is_voice_member(&mut conn, &source, &user).await);
        assert!(is_voice_member(&mut conn, &destination, &user).await);
        assert_eq!(
            recorded_connections(&mut conn, &destination).await,
            [("SID_D".to_string(), identity.clone())]
                .into_iter()
                .collect()
        );
        assert!(
            get_voice_state(&destination, &user)
                .await
                .unwrap()
                .is_some(),
            "the destination's state survives the late source leave"
        );
        assert_eq!(
            get_user_voice_channel_in_server(&user, destination.server_id.as_ref().unwrap())
                .await
                .unwrap(),
            Some(destination.id.clone())
        );

        delete_voice_state(&destination, &user)
            .await
            .expect("cleanup");
    }

    /// P2-1: "first" is decided on the voice state, never on the record's
    /// size. A stale sid then a rejoin still creates state (mutation n2,
    /// `HLEN == 1`, answers false); `delete_channel_voice_state` with no user
    /// ids — the `room_finished` / reconcile shape — clears the record
    /// (mutation n4).
    ///
    /// S-3 WA-R removed a third segment from here: a moderator's whole-user
    /// teardown between a sibling's record and its create, followed by the
    /// sibling's "next record" returning `true`. It re-recorded the same sid,
    /// which production never does (`participant_joined` fires once per
    /// sid), so it passed while the race it named was open (WA-1). The race
    /// is pinned, one record per sid, by
    /// `a_sibling_recorded_after_the_listing_keeps_the_state`.
    #[test]
    fn a_stale_record_never_hides_a_join() {
        rt().block_on(a_stale_record_never_hides_a_join_case())
    }

    async fn a_stale_record_never_hides_a_join_case() {
        let (channel, user, _) = connection_case_ids("P21");
        let mut conn = get_connection().await.expect("redis");

        // A missed leave left a stale entry behind.
        let _: () = conn
            .hset(format!("vc_conns:{}", channel.id), "SID_STALE", &user)
            .await
            .unwrap();
        assert!(
            record_voice_connection(&channel, &user, "SID_NEW", &user)
                .await
                .unwrap(),
            "a user with no voice state is a first connection, whatever the record holds"
        );
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();

        delete_channel_voice_state(&channel, &[]).await.unwrap();
        let record_exists: bool = conn
            .exists(format!("vc_conns:{}", channel.id))
            .await
            .unwrap();
        assert!(
            !record_exists,
            "the whole-call teardown with no user ids must DEL the connection record"
        );

        delete_channel_voice_state(&channel, &[user.clone()])
            .await
            .expect("cleanup");
    }

    /// S-3 WA-1, one record per sid as in production. Connection A records
    /// and gets state; the caller reads the record (the step every
    /// listing-driven teardown takes FIRST); connection B then records,
    /// answering `false` because state exists, so B never creates its own;
    /// the caller then removes exactly what it knew about, `[A]`. B must keep
    /// the state, the membership and its entry, and the mapping must name B.
    ///
    /// The pre-WA-R shape, a whole-user `delete_voice_state` in place of the
    /// set call, leaves B live, stateless and unrecorded: this test is red
    /// against it (mutation w4). Mutation w2 (set mode skips the survivor
    /// scan) is red here too.
    #[test]
    fn a_sibling_recorded_after_the_listing_keeps_the_state() {
        rt().block_on(a_sibling_recorded_after_the_listing_keeps_the_state_case())
    }

    async fn a_sibling_recorded_after_the_listing_keeps_the_state_case() {
        let (channel, user, server) = connection_case_ids("WA1");
        let (sibling_a, sibling_b) = (format!("{user}:A"), format!("{user}:B"));
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&channel, &user, "SID_A", &sibling_a)
            .await
            .unwrap());
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_voice_participant_identity(&channel.id, &user, &sibling_a)
            .await
            .unwrap();

        // The caller's snapshot, read BEFORE its listing.
        let recorded = recorded_voice_connections(&channel, &user).await.unwrap();
        assert_eq!(recorded, vec![("SID_A".to_string(), sibling_a.clone())]);
        let known: Vec<String> = recorded.into_iter().map(|(sid, _)| sid).collect();

        // B joins after the listing: state exists, so B creates none.
        assert!(
            !record_voice_connection(&channel, &user, "SID_B", &sibling_b)
                .await
                .unwrap(),
            "B joins a user who already holds state"
        );

        let leave = delete_voice_connections(&channel, &user, &known).await.unwrap();

        assert_eq!(leave, ConnectionLeave::Survivor);
        assert!(
            get_voice_state(&channel, &user).await.unwrap().is_some(),
            "B relied on the existing state; it must survive the removal of A"
        );
        assert!(is_voice_member(&mut conn, &channel, &user).await);
        assert!(get_user_voice_channels(&user).await.unwrap().contains(&channel));
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_B".to_string(), sibling_b.clone())].into_iter().collect(),
            "A's entry goes, B's stays"
        );
        assert_eq!(
            stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap(),
            Some(sibling_b.clone()),
            "the mapping names the survivor"
        );
        let flags: Vec<Option<String>> = conn.mget(per_server_keys(&user, &server)).await.unwrap();
        assert!(
            flags.iter().any(Option::is_some),
            "the per-server state is kept: {flags:?}"
        );

        delete_voice_state(&channel, &user).await.expect("cleanup");
    }

    /// S-3 WA-R set mode, the ownership rule (WA-6 for sets): a sid recorded
    /// as another user's is skipped, never HDELed, including a user whose id
    /// merely extends this one's (`{user}X:D`). With the user's own
    /// connection still recorded that is a `Survivor`; naming the user's own
    /// sid alongside the foreign one is the `Last`, and the other user keeps
    /// their entry and state throughout. Mutation w1 (set mode HDELs any
    /// given sid) deletes the other user's entry.
    #[test]
    fn a_set_teardown_never_removes_another_users_connection() {
        rt().block_on(a_set_teardown_never_removes_another_users_connection_case())
    }

    async fn a_set_teardown_never_removes_another_users_connection_case() {
        let (channel, user, _) = connection_case_ids("WAF");
        let other = format!("{user}X");
        let other_identity = format!("{other}:D");
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&channel, &user, "SID_U", &user)
            .await
            .unwrap());
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        assert!(
            record_voice_connection(&channel, &other, "SID_O", &other_identity)
                .await
                .unwrap()
        );
        create_voice_state(&channel, &other, Timestamp::now_utc())
            .await
            .unwrap();
        let both: std::collections::BTreeMap<String, String> = [
            ("SID_O".to_string(), other_identity.clone()),
            ("SID_U".to_string(), user.clone()),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            delete_voice_connections(&channel, &user, &["SID_O".to_string()])
                .await
                .unwrap(),
            ConnectionLeave::Survivor,
            "a foreign sid is skipped, and the user's own connection is still recorded"
        );
        assert_eq!(recorded_connections(&mut conn, &channel).await, both);
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());

        assert_eq!(
            delete_voice_connections(
                &channel,
                &user,
                &["SID_O".to_string(), "SID_U".to_string(), "SID_NONE".to_string()]
            )
            .await
            .unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &channel, &user).await);
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_O".to_string(), other_identity.clone())]
                .into_iter()
                .collect(),
            "the other user's entry is never removed"
        );
        assert!(get_voice_state(&channel, &other).await.unwrap().is_some());
        assert!(is_voice_member(&mut conn, &channel, &other).await);

        delete_channel_voice_state(&channel, &[other])
            .await
            .expect("cleanup");
    }

    /// S-3 WA-R set mode: naming every recorded sid of the user is the
    /// `Last` with the full teardown (state, membership, mapping, the
    /// per-server keys, the user's entries). And the EMPTY set, pinned as a
    /// survivor check: `Survivor` with nothing removed when the user has a
    /// recorded entry, `Last` with the full teardown when they have none (a
    /// legacy connection).
    #[test]
    fn a_set_teardown_of_every_connection_is_the_last_and_an_empty_set_checks() {
        rt().block_on(a_set_teardown_of_every_connection_is_the_last_and_an_empty_set_checks_case())
    }

    async fn a_set_teardown_of_every_connection_is_the_last_and_an_empty_set_checks_case() {
        let (channel, user, server) = connection_case_ids("WAL");
        let legacy = format!("{user}L");
        let mut conn = get_connection().await.expect("redis");

        for (sid, identity) in [("SID_1", user.clone()), ("SID_2", format!("{user}:D"))] {
            record_voice_connection(&channel, &user, sid, &identity)
                .await
                .unwrap();
        }
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_voice_participant_identity(&channel.id, &user, &user)
            .await
            .unwrap();

        // Empty set, the user recorded: a survivor check, nothing removed.
        assert_eq!(
            delete_voice_connections(&channel, &user, &[]).await.unwrap(),
            ConnectionLeave::Survivor
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());
        assert_eq!(recorded_connections(&mut conn, &channel).await.len(), 2);

        assert_eq!(
            delete_voice_connections(
                &channel,
                &user,
                &["SID_2".to_string(), "SID_1".to_string()]
            )
            .await
            .unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &channel, &user).await);
        assert!(!get_user_voice_channels(&user).await.unwrap().contains(&channel));
        assert_eq!(
            stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap(),
            None
        );
        assert!(recorded_connections(&mut conn, &channel).await.is_empty());
        let left: Vec<Option<String>> = conn.mget(per_server_keys(&user, &server)).await.unwrap();
        assert!(left.iter().all(Option::is_none), "{left:?}");

        // Empty set, the user never recorded: the full teardown.
        create_voice_state(&channel, &legacy, Timestamp::now_utc())
            .await
            .unwrap();
        assert_eq!(
            delete_voice_connections(&channel, &legacy, &[]).await.unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &legacy).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &channel, &legacy).await);
    }

    /// S-3 WA-6: connection mode refuses a sid recorded as ANOTHER user's
    /// with an error and nothing written: both users' entries and states
    /// intact, and the caller's watch session NOT ended (the Rust peek
    /// refuses before the session end; mutation w3a removes that check).
    /// The script refuses on its own too, before any write (mutation w3b),
    /// and so does the degraded fallback. A sid with no record at all is
    /// still not refused.
    #[test]
    fn a_connection_teardown_refuses_another_users_sid() {
        rt().block_on(a_connection_teardown_refuses_another_users_sid_case())
    }

    async fn a_connection_teardown_refuses_another_users_sid_case() {
        let (channel, user, _) = connection_case_ids("WA6");
        let other = format!("{user}O");
        let mut conn = get_connection().await.expect("redis");

        // The caller holds state with NO recorded connection (legacy) and
        // hosts a watch session, so without the peek's refusal the peek
        // would read "last" and end the session before the script refused.
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        let session = watch::create_watch_session(
            &channel.id,
            &user,
            v0::WatchMedia::YouTube {
                video_id: "YE7VzlLtp-4".to_string(),
                title: None,
            },
        )
        .await
        .unwrap()
        .expect("a fresh channel accepts a session");
        assert!(record_voice_connection(&channel, &other, "SID_O", &other)
            .await
            .unwrap());
        create_voice_state(&channel, &other, Timestamp::now_utc())
            .await
            .unwrap();
        let only_other: std::collections::BTreeMap<String, String> =
            [("SID_O".to_string(), other.clone())].into_iter().collect();

        async fn untouched(
            conn: &mut Conn,
            channel: &UserVoiceChannel,
            user: &str,
            other: &str,
            only_other: &std::collections::BTreeMap<String, String>,
            what: &str,
        ) {
            assert_eq!(&recorded_connections(conn, channel).await, only_other, "{what}");
            assert!(get_voice_state(channel, user).await.unwrap().is_some(), "{what}");
            assert!(get_voice_state(channel, other).await.unwrap().is_some(), "{what}");
            assert!(is_voice_member(conn, channel, user).await, "{what}");
            assert!(is_voice_member(conn, channel, other).await, "{what}");
        }

        assert!(
            delete_voice_connection(&channel, &user, "SID_O")
                .await
                .is_err(),
            "another user's sid must be refused, not deleted"
        );
        untouched(&mut conn, &channel, &user, &other, &only_other, "after the refusal").await;
        assert_eq!(
            watch::fetch_watch_session(&channel.id)
                .await
                .unwrap()
                .map(|kept| kept.id),
            Some(session.id.clone()),
            "the refusal comes before the watch session could end"
        );

        // The script on its own: an error reply, nothing written.
        let input = voice_connection_teardown_input(&channel, &user, "SID_O");
        let mut invocation = DELETE_VOICE_STATE.prepare_invoke();
        for key in &input.keys {
            invocation.key(key);
        }
        for arg in &input.args {
            invocation.arg(arg);
        }
        let refused = invocation
            .invoke_async::<_, i64>(&mut get_connection().await.unwrap().into_inner())
            .await;
        assert!(
            refused
                .as_ref()
                .is_err_and(teardown_refused_a_foreign_connection),
            "{refused:?}"
        );
        untouched(&mut conn, &channel, &user, &other, &only_other, "after the script").await;

        // The degraded fallback keeps the rule.
        assert!(
            delete_voice_connection_unconditionally(&channel, &user, "SID_O")
                .await
                .is_err()
        );
        untouched(&mut conn, &channel, &user, &other, &only_other, "after the fallback").await;

        // No record at all is not a refusal: the survivor scan decides, and
        // the caller has no recorded connection, so it is the `Last`.
        assert_eq!(
            delete_voice_connection(&channel, &user, "SID_NONE")
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
        assert_eq!(recorded_connections(&mut conn, &channel).await, only_other);

        delete_channel_voice_state(&channel, &[other])
            .await
            .expect("cleanup");
    }

    /// S-3 WA-R: `recorded_voice_connections` returns exactly the user's
    /// `(sid, identity)` pairs, ordered by sid: the bare and the
    /// device-qualified identity, never a lookalike user's `{user}u:B`.
    /// Mutation w5 (a bare `starts_with(user)`) includes it.
    #[test]
    fn the_recorded_connections_are_exactly_the_users() {
        rt().block_on(the_recorded_connections_are_exactly_the_users_case())
    }

    async fn the_recorded_connections_are_exactly_the_users_case() {
        let (channel, user, _) = connection_case_ids("RVC");
        let lookalike = format!("{user}u");

        for (sid, owner, identity) in [
            ("SID_2", user.clone(), format!("{user}:D")),
            ("SID_1", user.clone(), user.clone()),
            ("SID_3", lookalike.clone(), format!("{lookalike}:B")),
        ] {
            record_voice_connection(&channel, &owner, sid, &identity)
                .await
                .unwrap();
        }

        assert_eq!(
            recorded_voice_connections(&channel, &user).await.unwrap(),
            vec![
                ("SID_1".to_string(), user.clone()),
                ("SID_2".to_string(), format!("{user}:D")),
            ]
        );
        assert_eq!(
            recorded_voice_connections(&channel, &lookalike)
                .await
                .unwrap(),
            vec![("SID_3".to_string(), format!("{lookalike}:B"))]
        );
        assert!(
            recorded_voice_connections(&channel, "nobody")
                .await
                .unwrap()
                .is_empty()
        );

        delete_channel_voice_state(&channel, &[]).await.expect("cleanup");
    }

    /// S-3 WA-R: the degraded set fallback, driven directly, keeps the
    /// script's rules: a sibling outside the set survives (WA-1), a foreign
    /// sid is skipped, and the whole set is the `Last`.
    #[test]
    fn the_degraded_set_fallback_keeps_the_rules() {
        rt().block_on(the_degraded_set_fallback_keeps_the_rules_case())
    }

    async fn the_degraded_set_fallback_keeps_the_rules_case() {
        let (channel, user, _) = connection_case_ids("FBS");
        let other = format!("{user}O");
        let (first, second) = (format!("{user}:A"), format!("{user}:B"));
        let mut conn = get_connection().await.expect("redis");

        record_voice_connection(&channel, &user, "SID_A", &first)
            .await
            .unwrap();
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        record_voice_connection(&channel, &user, "SID_B", &second)
            .await
            .unwrap();
        record_voice_connection(&channel, &other, "SID_O", &other)
            .await
            .unwrap();

        assert_eq!(
            delete_voice_connections_unconditionally(
                &channel,
                &user,
                &["SID_A".to_string(), "SID_O".to_string()]
            )
            .await
            .unwrap(),
            ConnectionLeave::Survivor
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());
        assert_eq!(
            stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [
                ("SID_B".to_string(), second.clone()),
                ("SID_O".to_string(), other.clone()),
            ]
            .into_iter()
            .collect()
        );

        assert_eq!(
            delete_voice_connections_unconditionally(&channel, &user, &["SID_B".to_string()])
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_O".to_string(), other.clone())].into_iter().collect()
        );

        delete_channel_voice_state(&channel, &[other])
            .await
            .expect("cleanup");
    }

    /// P2-10: the whole-user teardown with two connections recorded is a full
    /// teardown — no survivor branch in that mode — and clears only this
    /// user's entries. Mutation n3 (the user mode takes the survivor branch)
    /// keeps the state. Also: an unknown mode is an error with nothing
    /// touched.
    #[test]
    fn a_whole_user_teardown_ignores_siblings() {
        rt().block_on(a_whole_user_teardown_ignores_siblings_case())
    }

    async fn a_whole_user_teardown_ignores_siblings_case() {
        let (channel, user, server) = connection_case_ids("P210");
        let other = format!("{user}O");
        let mut conn = get_connection().await.expect("redis");

        for (sid, identity) in [("SID_A", user.clone()), ("SID_B", format!("{user}:B"))] {
            record_voice_connection(&channel, &user, sid, &identity)
                .await
                .unwrap();
        }
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        record_voice_connection(&channel, &other, "SID_O", &other)
            .await
            .unwrap();
        create_voice_state(&channel, &other, Timestamp::now_utc())
            .await
            .unwrap();

        // A mode the script does not know is refused, and nothing moves.
        let mut input = voice_state_teardown_input(&channel, &user);
        input.args[3] = "bogus".to_string();
        let mut invocation = DELETE_VOICE_STATE.prepare_invoke();
        for key in &input.keys {
            invocation.key(key);
        }
        for arg in &input.args {
            invocation.arg(arg);
        }
        let refused = invocation
            .invoke_async::<_, i64>(&mut get_connection().await.unwrap().into_inner())
            .await;
        assert!(refused.is_err(), "{refused:?}");
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());
        assert_eq!(recorded_connections(&mut conn, &channel).await.len(), 3);

        delete_voice_state(&channel, &user).await.unwrap();
        assert!(
            get_voice_state(&channel, &user).await.unwrap().is_none(),
            "a whole-user teardown never keeps a sibling's state"
        );
        assert!(!is_voice_member(&mut conn, &channel, &user).await);
        let left: Vec<Option<String>> = conn.mget(per_server_keys(&user, &server)).await.unwrap();
        assert!(left.iter().all(Option::is_none), "{left:?}");
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_O".to_string(), other.clone())].into_iter().collect(),
            "every entry of the user goes, and only theirs"
        );
        assert!(get_voice_state(&channel, &other).await.unwrap().is_some());

        delete_channel_voice_state(&channel, &[other])
            .await
            .expect("cleanup");
    }

    /// P2-4: the watch session ends with the host's LAST connection, before
    /// the teardown, and a host whose sibling connection survives keeps it.
    /// Mutation n8 (the session ended on a survivor leave too) ends it early.
    #[test]
    fn the_watch_session_ends_with_the_hosts_last_connection() {
        rt().block_on(the_watch_session_ends_with_the_hosts_last_connection_case())
    }

    async fn the_watch_session_ends_with_the_hosts_last_connection_case() {
        let (channel, host, _) = connection_case_ids("P24");

        for (sid, identity) in [("SID_A", format!("{host}:A")), ("SID_B", format!("{host}:B"))] {
            record_voice_connection(&channel, &host, sid, &identity)
                .await
                .unwrap();
        }
        create_voice_state(&channel, &host, Timestamp::now_utc())
            .await
            .unwrap();
        let session = watch::create_watch_session(
            &channel.id,
            &host,
            v0::WatchMedia::YouTube {
                video_id: "YE7VzlLtp-4".to_string(),
                title: None,
            },
        )
        .await
        .unwrap()
        .expect("a fresh channel accepts a session");

        assert_eq!(
            delete_voice_connection(&channel, &host, "SID_A")
                .await
                .unwrap(),
            ConnectionLeave::Survivor
        );
        assert_eq!(
            watch::fetch_watch_session(&channel.id)
                .await
                .unwrap()
                .map(|kept| kept.id),
            Some(session.id),
            "a host whose other connection is still here keeps the session"
        );

        assert_eq!(
            delete_voice_connection(&channel, &host, "SID_B")
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(
            watch::fetch_watch_session(&channel.id)
                .await
                .unwrap()
                .is_none(),
            "the host's last connection ends the session"
        );
    }

    /// A watch host with two connections recorded, and a new watch
    /// session in the channel. Returns the session id.
    async fn watch_host_with_two_connections(channel: &UserVoiceChannel, host: &str) -> String {
        for (sid, identity) in [("SID_A", format!("{host}:A")), ("SID_B", format!("{host}:B"))] {
            record_voice_connection(channel, host, sid, &identity)
                .await
                .unwrap();
        }
        create_voice_state(channel, host, Timestamp::now_utc())
            .await
            .unwrap();
        watch::create_watch_session(
            &channel.id,
            host,
            v0::WatchMedia::YouTube {
                video_id: "YE7VzlLtp-4".to_string(),
                title: None,
            },
        )
        .await
        .unwrap()
        .expect("a fresh channel accepts a session")
        .id
    }

    /// S-3 RA2-4, set mode: a removal that names EVERY recorded connection
    /// of a watch host is the host's last, so the Rust peek
    /// (`another_connection_outside`) must end the session before the
    /// script tears the state down. The script never touches the session
    /// key, so only the peek can end it. Mutation x1 (the peek ignores
    /// `sids`, so the host's own named connections look like survivors)
    /// leaves the session orphaned after a `Last`.
    #[test]
    fn a_set_removal_of_every_host_connection_ends_the_watch_session() {
        rt().block_on(a_set_removal_of_every_host_connection_ends_the_watch_session_case())
    }

    async fn a_set_removal_of_every_host_connection_ends_the_watch_session_case() {
        let (channel, host, server) = connection_case_ids("RA24L");
        let mut conn = get_connection().await.expect("redis");
        let session = watch_host_with_two_connections(&channel, &host).await;
        assert_eq!(
            watch::fetch_watch_session(&channel.id)
                .await
                .unwrap()
                .map(|live| live.id),
            Some(session),
            "control: the session is live before the removal"
        );

        assert_eq!(
            delete_voice_connections(&channel, &host, &["SID_A".to_string(), "SID_B".to_string()])
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(
            watch::fetch_watch_session(&channel.id)
                .await
                .unwrap()
                .is_none(),
            "naming every connection of the host ends the watch session"
        );
        assert!(get_voice_state(&channel, &host).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &channel, &host).await);
        assert!(recorded_connections(&mut conn, &channel).await.is_empty());
        let left: Vec<Option<String>> = conn.mget(per_server_keys(&host, &server)).await.unwrap();
        assert!(left.iter().all(Option::is_none), "{left:?}");

        delete_channel_voice_state(&channel, &[host])
            .await
            .expect("cleanup");
    }

    /// S-3 RA2-4, set mode, the other direction: a removal that names ONE of
    /// a watch host's two recorded connections is a `Survivor`, and the host
    /// keeps the session. A peek that ended it on any named sid would end it
    /// early here.
    #[test]
    fn a_set_removal_of_one_host_connection_keeps_the_watch_session() {
        rt().block_on(a_set_removal_of_one_host_connection_keeps_the_watch_session_case())
    }

    async fn a_set_removal_of_one_host_connection_keeps_the_watch_session_case() {
        let (channel, host, _) = connection_case_ids("RA24S");
        let mut conn = get_connection().await.expect("redis");
        let session = watch_host_with_two_connections(&channel, &host).await;

        assert_eq!(
            delete_voice_connections(&channel, &host, &["SID_A".to_string()])
                .await
                .unwrap(),
            ConnectionLeave::Survivor
        );
        assert_eq!(
            watch::fetch_watch_session(&channel.id)
                .await
                .unwrap()
                .map(|kept| kept.id),
            Some(session),
            "a host whose other connection is still recorded keeps the session"
        );
        assert!(get_voice_state(&channel, &host).await.unwrap().is_some());
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_B".to_string(), format!("{host}:B"))]
                .into_iter()
                .collect()
        );

        delete_channel_voice_state(&channel, &[host])
            .await
            .expect("cleanup");
    }

    /// S-3 RA2 (unproven #2): connection mode takes exactly ONE sid. The
    /// public `delete_voice_connection` cannot express two, so the script is
    /// driven directly with a second sid appended to the connection-mode
    /// input: it answers an error reply and writes nothing (both entries,
    /// the state and the membership intact). The same input with one sid is
    /// the control: it runs, and answers the survivor. Mutation x2 (the
    /// `#ARGV ~= 5` guard removed) HDELs both and tears the state down.
    #[test]
    fn a_connection_mode_teardown_refuses_two_sids() {
        rt().block_on(a_connection_mode_teardown_refuses_two_sids_case())
    }

    async fn a_connection_mode_teardown_refuses_two_sids_case() {
        let (channel, user, _) = connection_case_ids("RA2N");
        let (first, second) = (format!("{user}:A"), format!("{user}:B"));
        let mut conn = get_connection().await.expect("redis");

        for (sid, identity) in [("SID_A", first.clone()), ("SID_B", second.clone())] {
            record_voice_connection(&channel, &user, sid, &identity)
                .await
                .unwrap();
        }
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        let both: std::collections::BTreeMap<String, String> = [
            ("SID_A".to_string(), first.clone()),
            ("SID_B".to_string(), second.clone()),
        ]
        .into_iter()
        .collect();

        let invoke = |input: VoiceStateTeardownInput| async move {
            let mut invocation = DELETE_VOICE_STATE.prepare_invoke();
            for key in &input.keys {
                invocation.key(key);
            }
            for arg in &input.args {
                invocation.arg(arg);
            }
            invocation
                .invoke_async::<_, i64>(&mut get_connection().await.unwrap().into_inner())
                .await
        };

        let mut two = voice_connection_teardown_input(&channel, &user, "SID_A");
        two.args.push("SID_B".to_string());
        assert_eq!(two.args.len(), 6, "{two:?}");
        let refused = invoke(two).await;
        assert!(
            refused.as_ref().is_err_and(|error| {
                error.kind() == ErrorKind::ResponseError
                    && error
                        .detail()
                        .is_some_and(|detail| detail.contains("connection mode takes one sid"))
            }),
            "{refused:?}"
        );
        assert_eq!(recorded_connections(&mut conn, &channel).await, both);
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());
        assert!(is_voice_member(&mut conn, &channel, &user).await);

        // Control: the one-sid input runs, and B is the survivor.
        assert_eq!(
            invoke(voice_connection_teardown_input(&channel, &user, "SID_A"))
                .await
                .unwrap(),
            TEARDOWN_SURVIVOR
        );
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_B".to_string(), second.clone())].into_iter().collect()
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());

        delete_channel_voice_state(&channel, &[user])
            .await
            .expect("cleanup");
    }

    /// The degraded fallbacks, driven directly (a server that refuses the
    /// script is not reachable here): the per-connection one re-points at a
    /// survivor and keeps the state, then tears down on the last; the
    /// whole-user one clears every entry of the user and only theirs.
    #[test]
    fn the_degraded_fallbacks_keep_the_connection_rules() {
        rt().block_on(the_degraded_fallbacks_keep_the_connection_rules_case())
    }

    async fn the_degraded_fallbacks_keep_the_connection_rules_case() {
        let (channel, user, _) = connection_case_ids("FB");
        let other = format!("{user}O");
        let (first, second) = (format!("{user}:A"), format!("{user}:B"));
        let mut conn = get_connection().await.expect("redis");

        record_voice_connection(&channel, &user, "SID_A", &first)
            .await
            .unwrap();
        record_voice_connection(&channel, &user, "SID_B", &second)
            .await
            .unwrap();
        record_voice_connection(&channel, &other, "SID_O", &other)
            .await
            .unwrap();
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_voice_participant_identity(&channel.id, &user, &first)
            .await
            .unwrap();

        assert_eq!(
            delete_voice_connection_unconditionally(&channel, &user, "SID_A")
                .await
                .unwrap(),
            ConnectionLeave::Survivor
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_some());
        assert_eq!(
            stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap(),
            Some(second.clone())
        );
        assert_eq!(
            delete_voice_connection_unconditionally(&channel, &user, "SID_B")
                .await
                .unwrap(),
            ConnectionLeave::Last
        );
        assert!(get_voice_state(&channel, &user).await.unwrap().is_none());

        record_voice_connection(&channel, &user, "SID_C", &first)
            .await
            .unwrap();
        record_voice_connection(&channel, &user, "SID_D", &second)
            .await
            .unwrap();
        delete_voice_state_unconditionally(&channel, &user)
            .await
            .unwrap();
        assert_eq!(
            recorded_connections(&mut conn, &channel).await,
            [("SID_O".to_string(), other.clone())].into_iter().collect()
        );

        delete_channel_voice_state(&channel, &[other])
            .await
            .expect("cleanup");
    }

    /// A screen leg, or another user's identity, is never recorded.
    #[test]
    fn only_a_primary_of_the_user_is_recorded() {
        rt().block_on(only_a_primary_of_the_user_is_recorded_case())
    }

    async fn only_a_primary_of_the_user_is_recorded_case() {
        let (channel, user, _) = connection_case_ids("LEG");
        let mut conn = get_connection().await.expect("redis");

        for identity in [
            screen_leg_identity(&user),
            screen_leg_identity(&format!("{user}:D")),
            format!("{user}X"),
            format!("{user}X:D"),
        ] {
            assert!(
                record_voice_connection(&channel, &user, "SID", &identity)
                    .await
                    .is_err(),
                "{identity} must not be recorded for {user}"
            );
        }
        assert!(recorded_connections(&mut conn, &channel).await.is_empty());
    }

    /// S-3 RA-2, on the real move against the Reference database: the
    /// pointer names D, the caller expected S. Moving to D is
    /// `AlreadyPresent` (it used to be `NotConnected`, a 400); moving to a
    /// third channel is still `NotConnected`. Both answers come before any
    /// SFU call, so a `VoiceClient` with no nodes is enough. Mutation n6
    /// (the order swapped back) answers the first `NotConnected`.
    #[test]
    fn a_move_to_where_the_target_already_is_is_already_present() {
        rt().block_on(a_move_to_where_the_target_already_is_is_already_present_case())
    }

    async fn a_move_to_where_the_target_already_is_is_already_present_case() {
        use crate::{Channel, Database, Member, Server, User};
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };

        let db = Database::Reference(Default::default());
        let owner = User::create(&db, "RaTwoOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "RaTwoServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;
        let mut voice = Vec::new();
        for name in ["Source", "Destination", "Third"] {
            voice.push(
                Channel::create_server_channel(
                    &db,
                    &mut server,
                    DataCreateServerChannel {
                        channel_type: LegacyServerChannelType::Voice,
                        name: name.to_string(),
                        ..Default::default()
                    },
                    true,
                )
                .await
                .expect("`Channel`"),
            );
        }
        let (source, destination, third) = (&voice[0], &voice[1], &voice[2]);
        let target = User::create(&db, "RaTwoTarget".to_string(), None, None)
            .await
            .expect("`User`");
        Member::create(&db, &server, &target, None)
            .await
            .expect("`Member`");

        let sitting_in = UserVoiceChannel::from_channel(destination);
        create_voice_state(&sitting_in, &target.id, Timestamp::now_utc())
            .await
            .unwrap();
        let voice_client = VoiceClient::new(Default::default());

        // Both answers come before the owner decision, so the policy and the
        // recorded session change nothing here: every combination is asked.
        // That includes a self-move from a SIBLING session, and one with no
        // owner recorded (merge slice SEC2-2): the move's own owner check
        // runs after both answers, so a same-channel self-move from any
        // session stays a no-op and a stale source stays `NotConnected`,
        // never `NotAuthenticated`.
        for (expected_session, policy) in [
            (Some("SESSION"), MovePolicy::Moderator),
            (None, MovePolicy::Moderator),
            (
                Some("SESSION"),
                MovePolicy::SelfMove {
                    request_session: Some("SESSION"),
                },
            ),
            (
                Some("SESSION"),
                MovePolicy::SelfMove {
                    request_session: Some("SIBLING"),
                },
            ),
            (
                None,
                MovePolicy::SelfMove {
                    request_session: Some("SIBLING"),
                },
            ),
            (None, MovePolicy::Sweep),
        ] {
            assert_eq!(
                move_user_to_voice_channel_expecting(
                    &db,
                    &voice_client,
                    &target,
                    destination,
                    source.id(),
                    expected_session,
                    policy,
                )
                .await
                .unwrap(),
                VoiceMoveOutcome::AlreadyPresent,
                "a target already in the destination is AlreadyPresent, whatever source was \
                 expected ({expected_session:?}, {policy:?})"
            );
            assert_eq!(
                move_user_to_voice_channel_expecting(
                    &db,
                    &voice_client,
                    &target,
                    third,
                    source.id(),
                    expected_session,
                    policy,
                )
                .await
                .unwrap(),
                VoiceMoveOutcome::NotConnected,
                "control: a target who left the expected source is NotConnected for any other \
                 destination ({expected_session:?}, {policy:?})"
            );
        }

        delete_voice_state(&sitting_in, &target.id)
            .await
            .expect("cleanup");
    }

    /// S-3 D-3 against the Reference database: the re-check answers exactly
    /// what the join route's calculus answers. Allowed: a member with
    /// Connect, a bot member with Connect, a Group participant, a DM
    /// participant, the server OWNER under a Connect denial (GrantAllSafe).
    /// Refused: a non-member, a member under the denial, a user outside the
    /// DM. A missing user or channel is `Ok(false)`. Mutation n7 (an explicit
    /// member lookup) refuses the DM and the Group.
    #[test]
    fn the_connect_recheck_follows_the_join_calculus() {
        rt().block_on(the_connect_recheck_follows_the_join_calculus_case())
    }

    async fn the_connect_recheck_follows_the_join_calculus_case() {
        use crate::{Bot, Channel, Database, Member, PartialBot, PartialChannel, Server, User};
        use revolt_models::v0::{
            DataCreateGroup, DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };
        use revolt_permissions::OverrideField;

        let db = Database::Reference(Default::default());
        let owner = User::create(&db, "RecheckOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "RecheckServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;
        let mut voice = Channel::create_server_channel(
            &db,
            &mut server,
            DataCreateServerChannel {
                channel_type: LegacyServerChannelType::Voice,
                name: "Voice".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`");
        let member = User::create(&db, "RecheckMember".to_string(), None, None)
            .await
            .expect("`User`");
        Member::create(&db, &server, &member, None)
            .await
            .expect("`Member`");
        let outsider = User::create(&db, "RecheckOutsider".to_string(), None, None)
            .await
            .expect("`User`");
        let (_, bot) = Bot::create(&db, "RecheckBot".to_string(), &owner, None::<PartialBot>)
            .await
            .expect("`Bot`");
        Member::create(&db, &server, &bot, None)
            .await
            .expect("`Member`");

        // No move admission exists for any of these, so the joining identity
        // (the bare seat) changes nothing: the calculus alone answers.
        async fn allowed(db: &Database, channel_id: &str, user_id: &str) -> bool {
            voice_connect_still_allowed(db, channel_id, user_id, user_id)
                .await
                .expect("the re-check reads")
        }

        assert!(allowed(&db, voice.id(), &member.id).await, "a member with Connect");
        assert!(allowed(&db, voice.id(), &bot.id).await, "a bot member with Connect");
        assert!(!allowed(&db, voice.id(), &outsider.id).await, "a non-member");

        // A Group owned by the member with the outsider in it, then a DM
        // between the two, whose mutual Group is what lets the DM speak.
        let group = Channel::create_group(
            &db,
            DataCreateGroup {
                name: "RecheckGroup".to_string(),
                users: [outsider.id.clone()].into_iter().collect(),
                ..Default::default()
            },
            member.id.clone(),
        )
        .await
        .expect("`Group`");
        assert!(allowed(&db, group.id(), &outsider.id).await, "a Group participant");
        let dm = Channel::create_dm(&db, &member, &outsider)
            .await
            .expect("`DirectMessage`");
        assert!(allowed(&db, dm.id(), &outsider.id).await, "a DM participant");
        assert!(!allowed(&db, dm.id(), &owner.id).await, "control: not in the DM");

        voice
            .update(
                &db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::Connect as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("channel override");
        assert!(!allowed(&db, voice.id(), &member.id).await, "a member denied Connect");
        assert!(
            allowed(&db, voice.id(), &owner.id).await,
            "the server owner is GrantAllSafe, before any override"
        );

        assert!(!allowed(&db, "01KX7J0000NOSUCHCHANNEL0000", &member.id).await);
        assert!(!allowed(&db, voice.id(), "01KX7J0000NOSUCHUSER000000").await);
    }

    // ---- S-3 lane B1: the roster-driven sync, the server-wide sync, and
    // the removal that deletes only what it knows ----
    //
    // The REAL functions against Redis on the shared runtime, the mock SFU
    // (`voice_client::sfu_stub`, whose ordered `(path, identity)` log is the
    // observable) and the Reference database. ULID-suffixed ids throughout.

    use super::voice_client::sfu_stub as stub;
    use crate::{Channel, Database, Server, User};

    fn sfu_requests(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(path, identity)| (path.to_string(), identity.to_string()))
            .collect()
    }

    /// A stub listing `(sid, identity)` pairs, answering every
    /// `UpdateParticipant` with a 200 (and keeping the permission it
    /// carried) and anything else with a 500.
    fn roster_stub(
        roster: &[(&str, &str)],
    ) -> (
        stub::Stub,
        std::sync::Arc<std::sync::Mutex<Vec<livekit_protocol::ParticipantPermission>>>,
    ) {
        let triples: Vec<(&str, &str, &str)> = roster
            .iter()
            .map(|(sid, identity)| (*sid, *identity, ""))
            .collect();
        let listing = stub::list_participants_response_sids(&triples);
        let pushed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sfu = {
            let pushed = pushed.clone();
            stub::Stub::serve(move |path, body| match path {
                stub::LIST => stub::ok(listing.clone()),
                stub::UPDATE => {
                    pushed
                        .lock()
                        .unwrap()
                        .push(stub::permission(body).expect("an update carries a permission"));
                    stub::ok(Vec::new())
                }
                _ => stub::internal(),
            })
        };
        (sfu, pushed)
    }

    /// A stub listing `(sid, identity)` pairs and answering every
    /// `RemoveParticipant` with `remove`.
    fn eviction_stub(roster: &[(&str, &str)], remove: stub::Reply) -> stub::Stub {
        let triples: Vec<(&str, &str, &str)> = roster
            .iter()
            .map(|(sid, identity)| (*sid, *identity, ""))
            .collect();
        stub::Stub::serve(stub::routes(vec![
            (
                stub::LIST,
                stub::ok(stub::list_participants_response_sids(&triples)),
            ),
            (stub::REMOVE, remove),
        ]))
    }

    /// A server with a voice channel and one member who is not its owner, in
    /// a fresh Reference database.
    async fn sync_fixture(tag: &str) -> (Database, Server, Channel, User) {
        use crate::Member;
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };

        let db = Database::Reference(Default::default());
        let owner = User::create(&db, format!("B1Owner{tag}"), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: format!("B1Server{tag}"),
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
        let member = User::create(&db, format!("B1Member{tag}"), None, None)
            .await
            .expect("`User`");
        Member::create(&db, &server, &member, None)
            .await
            .expect("`Member`");

        (db, server, channel, member)
    }

    /// D-4: the mapping names `U:D1`, the SFU lists `[U, U:D1]`. The room
    /// sync pushes BOTH, in listed order, after ONE listing, and both get
    /// the same primary set. The pre-B1 sync resolved the mapping and
    /// reached `U:D1` alone. Mutation b6 (the push handed only the first
    /// connection) leaves `U:D1` unpushed.
    #[test]
    fn the_room_sync_pushes_every_listed_connection() {
        rt().block_on(the_room_sync_pushes_every_listed_connection_case())
    }

    async fn the_room_sync_pushes_every_listed_connection_case() {
        let (db, server, channel, member) = sync_fixture("R1").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        let device = format!("{}:D1", member.id);

        set_channel_node(channel.id(), stub::NODE).await.unwrap();
        assert!(
            record_voice_connection(&uvc, &member.id, "SID_U", &member.id)
                .await
                .unwrap()
        );
        create_voice_state(&uvc, &member.id, Timestamp::now_utc())
            .await
            .unwrap();
        assert!(
            !record_voice_connection(&uvc, &member.id, "SID_D1", &device)
                .await
                .unwrap()
        );
        set_voice_participant_identity(channel.id(), &member.id, &device)
            .await
            .unwrap();

        let (sfu, pushed) = roster_stub(&[("SID_U", &member.id), ("SID_D1", &device)]);
        let result = sync_voice_permissions(
            &db,
            &stub::voice_client(sfu.url()),
            &channel,
            Some(&server),
            None,
        )
        .await;
        let seen = sfu.finish();

        delete_voice_state(&uvc, &member.id).await.expect("cleanup");
        delete_channel_node(channel.id()).await.expect("cleanup");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            seen,
            sfu_requests(&[
                (stub::LIST, ""),
                (stub::UPDATE, &member.id),
                (stub::UPDATE, &device),
            ]),
            "one listing, then every listed connection of the user"
        );
        let pushed = pushed.lock().unwrap();
        assert_eq!(pushed.len(), 2);
        assert_eq!(pushed[0], pushed[1], "both primaries get the same set");
        assert!(
            pushed[0].can_subscribe && !pushed[0].can_publish_data,
            "{:?}",
            pushed[0]
        );
    }

    /// D-4 / F-2: a member the SFU lists who has NO voice state here and is
    /// not in `vc_members` is pushed the grant, and nothing is written: no
    /// state, no membership, no per-server key. Mutation b7 (that arm
    /// answering `Synced` without the push) leaves them with whatever grant
    /// they were minted.
    #[test]
    fn a_listed_user_with_no_voice_state_is_pushed_and_nothing_is_written() {
        rt().block_on(a_listed_user_with_no_voice_state_is_pushed_and_nothing_is_written_case())
    }

    async fn a_listed_user_with_no_voice_state_is_pushed_and_nothing_is_written_case() {
        let (db, server, channel, member) = sync_fixture("R2").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        let mut conn = get_connection().await.expect("redis");

        set_channel_node(channel.id(), stub::NODE).await.unwrap();

        let (sfu, pushed) = roster_stub(&[("SID_V", &member.id)]);
        let result = sync_voice_permissions(
            &db,
            &stub::voice_client(sfu.url()),
            &channel,
            Some(&server),
            None,
        )
        .await;
        let seen = sfu.finish();
        delete_channel_node(channel.id()).await.expect("cleanup");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            seen,
            sfu_requests(&[(stub::LIST, ""), (stub::UPDATE, &member.id)]),
            "the stateless live connection is pushed"
        );
        assert_eq!(pushed.lock().unwrap().len(), 1);
        assert!(get_voice_state(&uvc, &member.id).await.unwrap().is_none());
        assert!(!is_voice_member(&mut conn, &uvc, &member.id).await);
        assert!(!get_user_voice_channels(&member.id)
            .await
            .unwrap()
            .contains(&uvc));
        let written: Vec<Option<String>> = conn
            .mget(per_server_keys(&member.id, &server.id))
            .await
            .unwrap();
        assert!(written.iter().all(Option::is_none), "{written:?}");
    }

    /// The single-user entry point lists the room ITSELF, once: `[U, U:D1]`
    /// are both pushed. With voice state and nothing of theirs listed it
    /// answers the `InternalError` it always answered for a participant the
    /// SFU does not have, after the one listing and no push.
    #[test]
    fn the_single_user_sync_lists_the_room_itself() {
        rt().block_on(the_single_user_sync_lists_the_room_itself_case())
    }

    async fn the_single_user_sync_lists_the_room_itself_case() {
        let (db, server, channel, member) = sync_fixture("R3").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        let device = format!("{}:D1", member.id);

        create_voice_state(&uvc, &member.id, Timestamp::now_utc())
            .await
            .unwrap();

        let (sfu, _) = roster_stub(&[("SID_U", &member.id), ("SID_D1", &device)]);
        let both = sync_user_voice_permissions(
            &db,
            &stub::voice_client(sfu.url()),
            stub::NODE,
            &member,
            &channel,
            Some(&server),
            None,
        )
        .await;
        let both_seen = sfu.finish();

        let (sfu, _) = roster_stub(&[("SID_X", "01KX7J0000SOMEONEELSE00000")]);
        let none = sync_user_voice_permissions(
            &db,
            &stub::voice_client(sfu.url()),
            stub::NODE,
            &member,
            &channel,
            Some(&server),
            None,
        )
        .await;
        let none_seen = sfu.finish();

        delete_voice_state(&uvc, &member.id).await.expect("cleanup");

        assert!(both.is_ok(), "{both:?}");
        assert_eq!(
            both_seen,
            sfu_requests(&[
                (stub::LIST, ""),
                (stub::UPDATE, &member.id),
                (stub::UPDATE, &device),
            ])
        );
        assert!(
            matches!(&none, Err(error) if matches!(error.error_type, revolt_result::ErrorType::InternalError)),
            "{none:?}"
        );
        assert_eq!(none_seen, sfu_requests(&[(stub::LIST, "")]));
    }

    /// S-3 B1-R: the roster flags land in Redis BEFORE any SFU contact, so a
    /// ListParticipants that answers 500 still leaves the change written.
    /// The channel is the server's AFK channel (so a publishing member's
    /// `is_publishing` must become false) and the member holds voice state.
    /// Both entry points answer the listing's error, push nothing, and
    /// still wrote the flag: the single-user one (the path `member_edit`
    /// takes) and the room-wide one, which walks its members as `Unlisted`.
    /// Mutations r1 (the single-user listing moved back above the write) and
    /// r2 (the room returning on the failed listing before its members)
    /// each leave `is_publishing` true.
    #[test]
    fn a_failed_listing_still_writes_the_roster_flags() {
        rt().block_on(a_failed_listing_still_writes_the_roster_flags_case())
    }

    async fn a_failed_listing_still_writes_the_roster_flags_case() {
        let (db, mut server, channel, member) = sync_fixture("L1").await;
        server.afk_channel_id = Some(channel.id().to_string());
        let uvc = UserVoiceChannel::from_channel(&channel);
        let publishing = PartialUserVoiceState {
            is_publishing: Some(true),
            ..Default::default()
        };

        create_voice_state(&uvc, &member.id, Timestamp::now_utc())
            .await
            .unwrap();
        set_channel_node(channel.id(), stub::NODE).await.unwrap();

        update_voice_state(&uvc, &member.id, &publishing)
            .await
            .unwrap();
        let sfu = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]));
        let single = sync_user_voice_permissions(
            &db,
            &stub::voice_client(sfu.url()),
            stub::NODE,
            &member,
            &channel,
            Some(&server),
            None,
        )
        .await;
        let single_seen = sfu.finish();
        let single_state = get_voice_state(&uvc, &member.id).await.unwrap();

        update_voice_state(&uvc, &member.id, &publishing)
            .await
            .unwrap();
        let sfu = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]));
        let room = sync_voice_permissions(
            &db,
            &stub::voice_client(sfu.url()),
            &channel,
            Some(&server),
            None,
        )
        .await;
        let room_seen = sfu.finish();
        let room_state = get_voice_state(&uvc, &member.id).await.unwrap();

        delete_voice_state(&uvc, &member.id).await.expect("cleanup");
        delete_channel_node(channel.id()).await.expect("cleanup");

        assert!(
            matches!(&single, Err(error) if matches!(error.error_type, revolt_result::ErrorType::InternalError)),
            "single-user: the listing's error is the answer: {single:?}"
        );
        assert_eq!(single_seen, sfu_requests(&[(stub::LIST, "")]), "no push");
        assert!(
            !single_state.expect("state kept").is_publishing,
            "single-user: the flag is written before the listing"
        );
        assert!(
            matches!(&room, Err(error) if matches!(error.error_type, revolt_result::ErrorType::InternalError)),
            "room: the listing's error is the answer: {room:?}"
        );
        assert_eq!(room_seen, sfu_requests(&[(stub::LIST, "")]), "no push");
        assert!(
            !room_state.expect("state kept").is_publishing,
            "room: a member with state still gets the flag written"
        );
    }

    /// D-6, the walk with a fake per-channel sync: ch1 fails, ch2 is gone,
    /// ch3 fails, ch4 syncs. All four are tried, in order, and the FIRST
    /// failure (ch1's) is the answer. Mutation b8 (an exit in the shared
    /// loop on the first failure) stops at ch1.
    #[test]
    fn the_server_sync_tries_every_channel_and_returns_the_first_failure() {
        rt().block_on(the_server_sync_tries_every_channel_and_returns_the_first_failure_case())
    }

    async fn the_server_sync_tries_every_channel_and_returns_the_first_failure_case() {
        let (_, mut server, _, _) = sync_fixture("S1").await;
        server.channels = ["ch1", "ch2", "ch3", "ch4"].map(str::to_string).to_vec();

        let tried = std::sync::Mutex::new(Vec::new());
        let result = sync_server_channels(&server, |channel_id: String| {
            tried.lock().unwrap().push(channel_id.clone());
            async move {
                match channel_id.as_str() {
                    "ch1" => MemberSync::Failed(revolt_result::create_error!(InvalidOperation)),
                    "ch2" => MemberSync::Gone(revolt_result::create_error!(NotFound)),
                    "ch3" => MemberSync::Failed(revolt_result::create_error!(InternalError)),
                    _ => MemberSync::Synced,
                }
            }
        })
        .await;

        assert_eq!(
            *tried.lock().unwrap(),
            ["ch1", "ch2", "ch3", "ch4"],
            "every channel is tried, in order, whatever the one before it did"
        );
        match result {
            Err(error) => assert!(
                matches!(error.error_type, revolt_result::ErrorType::InvalidOperation),
                "the FIRST failure is the answer: {error:?}"
            ),
            Ok(()) => panic!("two channels failed"),
        }
    }

    /// D-6 wiring, end to end: a channel whose node is pinned but whose
    /// document is gone is skipped (not a failure), a channel with no call
    /// is skipped, and a live call is listed. Then a call whose listing
    /// fails fails the sync, and the call after it is STILL listed.
    #[test]
    fn the_server_sync_skips_the_gone_and_the_idle_and_tries_every_call() {
        rt().block_on(the_server_sync_skips_the_gone_and_the_idle_and_tries_every_call_case())
    }

    async fn the_server_sync_skips_the_gone_and_the_idle_and_tries_every_call_case() {
        use revolt_models::v0::{DataCreateServerChannel, LegacyServerChannelType};

        let (db, mut server, failing_call, _) = sync_fixture("S2").await;
        let live_call = Channel::create_server_channel(
            &db,
            &mut server,
            DataCreateServerChannel {
                channel_type: LegacyServerChannelType::Voice,
                name: "Second".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`");
        let suffix = ulid::Ulid::new().to_string();
        let (gone, idle) = (format!("gone{suffix}"), format!("idle{suffix}"));

        let failing = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]));
        let healthy = stub::Stub::serve(stub::routes(vec![(
            stub::LIST,
            stub::ok(stub::list_participants_response_sids(&[])),
        )]));
        let voice_client = stub::voice_client_nodes(
            &[("nodeF", failing.url()), ("nodeH", healthy.url())],
            SFU_CALL_TIMEOUT,
            SFU_BREAKER_WINDOW,
        );
        set_channel_node(failing_call.id(), "nodeF").await.unwrap();
        set_channel_node(&gone, "nodeH").await.unwrap();
        set_channel_node(live_call.id(), "nodeH").await.unwrap();

        server.channels = vec![gone.clone(), idle.clone(), live_call.id().to_string()];
        let skipped = sync_server_voice_permissions(&db, &voice_client, &server, None).await;
        let skipped_seen = healthy.seen();

        server.channels = vec![failing_call.id().to_string(), live_call.id().to_string()];
        let failed = sync_server_voice_permissions(&db, &voice_client, &server, None).await;

        for channel_id in [failing_call.id(), gone.as_str(), live_call.id()] {
            delete_channel_node(channel_id).await.expect("cleanup");
        }

        assert!(
            skipped.is_ok(),
            "the gone and the idle channel are skipped: {skipped:?}"
        );
        assert_eq!(
            skipped_seen,
            sfu_requests(&[(stub::LIST, "")]),
            "only the live call"
        );
        assert!(failed.is_err(), "{failed:?}");
        assert_eq!(failing.finish(), sfu_requests(&[(stub::LIST, "")]));
        assert_eq!(
            healthy.finish(),
            sfu_requests(&[(stub::LIST, ""), (stub::LIST, "")]),
            "the call after the failing one is still synced"
        );
    }

    /// D-2: `remove_user_from_server_voice` over two calls, the first
    /// eviction failing. The second call is STILL tried and torn down; the
    /// first keeps its state and record (no teardown on a failed eviction);
    /// the answer is the failure. Mutation b4 (`?` on the per-channel
    /// removal) never reaches the second call.
    #[test]
    fn the_server_removal_tries_every_call_after_a_failure() {
        rt().block_on(the_server_removal_tries_every_call_after_a_failure_case())
    }

    async fn the_server_removal_tries_every_call_after_a_failure_case() {
        let (db, mut server, _, _) = sync_fixture("X1").await;
        let suffix = ulid::Ulid::new().to_string();
        let user = format!("userX1{suffix}");
        let first_call = UserVoiceChannel {
            id: format!("chanX1a{suffix}"),
            server_id: Some(server.id.clone()),
        };
        let second_call = UserVoiceChannel {
            id: format!("chanX1b{suffix}"),
            server_id: Some(server.id.clone()),
        };
        server.channels = vec![first_call.id.clone(), second_call.id.clone()];
        let mut conn = get_connection().await.expect("redis");

        for (channel, sid) in [(&first_call, "SID1"), (&second_call, "SID2")] {
            assert!(record_voice_connection(channel, &user, sid, &user)
                .await
                .unwrap());
            create_voice_state(channel, &user, Timestamp::now_utc())
                .await
                .unwrap();
        }
        set_channel_node(&first_call.id, "node1").await.unwrap();
        set_channel_node(&second_call.id, "node2").await.unwrap();

        let failing = eviction_stub(&[("SID1", &user)], stub::internal());
        let healthy = eviction_stub(&[("SID2", &user)], stub::ok(Vec::new()));
        let voice_client = stub::voice_client_nodes(
            &[("node1", failing.url()), ("node2", healthy.url())],
            SFU_CALL_TIMEOUT,
            SFU_BREAKER_WINDOW,
        );

        let result = remove_user_from_server_voice(&db, &voice_client, &server, &user).await;
        let (failing_seen, healthy_seen) = (failing.finish(), healthy.finish());

        let first_member = is_voice_member(&mut conn, &first_call, &user).await;
        let first_record = recorded_connections(&mut conn, &first_call).await;
        let second_member = is_voice_member(&mut conn, &second_call, &user).await;
        let second_record = recorded_connections(&mut conn, &second_call).await;

        delete_voice_state(&first_call, &user)
            .await
            .expect("cleanup");
        delete_voice_state(&second_call, &user)
            .await
            .expect("cleanup");
        delete_channel_node(&first_call.id).await.expect("cleanup");
        delete_channel_node(&second_call.id).await.expect("cleanup");

        let evictions = sfu_requests(&[
            (stub::LIST, ""),
            (stub::REMOVE, &format!("{user}::screen")),
            (stub::REMOVE, &user),
        ]);
        assert!(result.is_err(), "{result:?}");
        assert_eq!(failing_seen, evictions);
        assert_eq!(healthy_seen, evictions, "the second call is still tried");
        assert!(!second_member, "the second call's state is torn down");
        assert!(second_record.is_empty(), "{second_record:?}");
        assert!(first_member, "no teardown after the failed eviction");
        assert_eq!(
            first_record,
            [("SID1".to_string(), user.clone())].into_iter().collect()
        );
    }

    /// D-2 / P2-6: the channel the per-server pointer names is torn down
    /// even with no node pinned (a ghost whose call has ended), through the
    /// removal's no-node branch, with no SFU call at all. Mutation b9 (the
    /// pointer's channel dropped from the walk) leaves the ghost.
    #[test]
    fn the_server_removal_clears_the_pointer_ghost_without_a_node() {
        rt().block_on(the_server_removal_clears_the_pointer_ghost_without_a_node_case())
    }

    async fn the_server_removal_clears_the_pointer_ghost_without_a_node_case() {
        let (db, mut server, _, _) = sync_fixture("X2").await;
        let suffix = ulid::Ulid::new().to_string();
        let user = format!("userX2{suffix}");
        let ghost = UserVoiceChannel {
            id: format!("chanX2{suffix}"),
            server_id: Some(server.id.clone()),
        };
        server.channels = vec![ghost.id.clone()];
        let mut conn = get_connection().await.expect("redis");

        create_voice_state(&ghost, &user, Timestamp::now_utc())
            .await
            .unwrap();

        // No node anywhere: any SFU call would be an UnknownNode failure.
        let result = remove_user_from_server_voice(
            &db,
            &VoiceClient::new(Default::default()),
            &server,
            &user,
        )
        .await;

        let member = is_voice_member(&mut conn, &ghost, &user).await;
        let left: Vec<Option<String>> =
            conn.mget(per_server_keys(&user, &server.id)).await.unwrap();
        delete_voice_state(&ghost, &user).await.expect("cleanup");

        assert!(result.is_ok(), "{result:?}");
        assert!(!member, "the ghost's membership is gone");
        assert!(left.iter().all(Option::is_none), "{left:?}");
        assert!(!get_user_voice_channels(&user)
            .await
            .unwrap()
            .contains(&ghost));
    }

    /// WA-1 at the CALLER: connection A is recorded; the removal reads the
    /// record; then sibling B records (answering "state exists", so it
    /// creates none) and is NOT in the listing the SFU then returns. A is
    /// evicted and its record deleted; B keeps the state, the membership,
    /// its record and the mapping. Driven through the real
    /// `remove_user_from_voice_channel`: the stub records B from inside its
    /// listing handler, so B lands strictly after the removal's record read
    /// and strictly before its teardown. Mutation b1 (the record read moved
    /// below the listing) names B as stale and tears its state down.
    #[test]
    fn a_connection_recorded_after_the_removal_read_survives_it() {
        rt().block_on(a_connection_recorded_after_the_removal_read_survives_it_case())
    }

    async fn a_connection_recorded_after_the_removal_read_survives_it_case() {
        let (channel, user, server) = connection_case_ids("RW1");
        let (a, b) = (format!("{user}:A"), format!("{user}:B"));
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&channel, &user, "SID_A", &a)
            .await
            .unwrap());
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_voice_participant_identity(&channel.id, &user, &a)
            .await
            .unwrap();
        set_channel_node(&channel.id, stub::NODE).await.unwrap();

        let listing = stub::list_participants_response_sids(&[("SID_A", &a, "")]);
        let late = std::sync::Arc::new(std::sync::Mutex::new(None));
        let sfu = {
            let late = late.clone();
            let (channel, user, b) = (channel.clone(), user.clone(), b.clone());
            stub::Stub::serve(move |path, _| match path {
                stub::LIST => {
                    // B joins now: after the removal's record read, and
                    // not in the listing answered below.
                    let recorded =
                        rt().block_on(record_voice_connection(&channel, &user, "SID_B", &b));
                    *late.lock().unwrap() = Some(recorded.map_err(|error| format!("{error:?}")));
                    stub::ok(listing.clone())
                }
                stub::REMOVE => stub::ok(Vec::new()),
                _ => stub::internal(),
            })
        };

        let result =
            remove_user_from_voice_channel(&db, &stub::voice_client(sfu.url()), &channel, &user)
                .await;
        let seen = sfu.finish();

        let state = get_voice_state(&channel, &user).await.unwrap();
        let member = is_voice_member(&mut conn, &channel, &user).await;
        let record = recorded_connections(&mut conn, &channel).await;
        let mapping = stored_voice_participant_identity(&channel.id, &user)
            .await
            .unwrap();
        let flags: Vec<Option<String>> = conn.mget(per_server_keys(&user, &server)).await.unwrap();

        delete_voice_state(&channel, &user).await.expect("cleanup");
        delete_channel_node(&channel.id).await.expect("cleanup");

        assert_eq!(
            *late.lock().unwrap(),
            Some(Ok(false)),
            "B joined a user who already held state, so it created none"
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            seen,
            sfu_requests(&[
                (stub::LIST, ""),
                (stub::REMOVE, &format!("{a}:screen")),
                (stub::REMOVE, &a),
            ]),
            "only the listed connection is evicted"
        );
        assert!(
            state.is_some(),
            "B relied on the existing state; it must survive"
        );
        assert!(member);
        assert_eq!(
            record,
            [("SID_B".to_string(), b.clone())].into_iter().collect(),
            "A's record goes, B's stays"
        );
        assert_eq!(mapping, Some(b.clone()), "the mapping names the survivor");
        assert!(flags.iter().any(Option::is_some), "{flags:?}");
    }

    /// D-2: a failed eviction (the SFU answers the listed connection's
    /// removal with a 500) returns the error with NOTHING torn down: the
    /// state, the membership and the record all stay, so the connection
    /// that may still be live stays visible and syncable. Mutation b3 (the
    /// eviction's error swallowed into "no listing") tears it all down.
    #[test]
    fn a_failed_eviction_tears_nothing_down() {
        rt().block_on(a_failed_eviction_tears_nothing_down_case())
    }

    async fn a_failed_eviction_tears_nothing_down_case() {
        let (channel, user, _) = connection_case_ids("RE1");
        let a = format!("{user}:A");
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&channel, &user, "SID_A", &a)
            .await
            .unwrap());
        create_voice_state(&channel, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_channel_node(&channel.id, stub::NODE).await.unwrap();

        let sfu = eviction_stub(&[("SID_A", &a)], stub::internal());
        let result =
            remove_user_from_voice_channel(&db, &stub::voice_client(sfu.url()), &channel, &user)
                .await;
        let seen = sfu.finish();

        let state = get_voice_state(&channel, &user).await.unwrap();
        let member = is_voice_member(&mut conn, &channel, &user).await;
        let record = recorded_connections(&mut conn, &channel).await;

        delete_voice_state(&channel, &user).await.expect("cleanup");
        delete_channel_node(&channel.id).await.expect("cleanup");

        assert!(
            matches!(&result, Err(error) if matches!(error.error_type, revolt_result::ErrorType::InternalError)),
            "{result:?}"
        );
        assert_eq!(
            seen,
            sfu_requests(&[
                (stub::LIST, ""),
                (stub::REMOVE, &format!("{a}:screen")),
                (stub::REMOVE, &a),
            ])
        );
        assert!(state.is_some(), "no teardown after a failed eviction");
        assert!(member);
        assert_eq!(
            record,
            [("SID_A".to_string(), a.clone())].into_iter().collect()
        );
    }

    /// AFK S-3 WBR-3: the SFU LISTS a connection of a user Redis knows
    /// nothing of here (no record, no state: a join that lost the webhook
    /// race), and its removal is answered 500. The connection may still be
    /// live, so the removal answers the ERROR, whatever Redis holds: a kick
    /// or ban must not answer 200 over it. It used to share the WB-2 `Ok` of
    /// a room that could not be listed at all, because both failures were
    /// one untyped `Err`. The remote-control release runs before the error
    /// returns, revoking: the user sharing here has their grant ended.
    ///
    /// Control, the WB-2 arm this must not swallow: the LISTING answered
    /// 500, the same user with nothing in Redis, is still `Ok`, with no
    /// release and no script.
    ///
    /// Red at `7fb70a98` (the listed case answered `Ok`, with no release).
    /// Mutations: the `Listed` arm sent to the WB-2 report (`Ok`); its
    /// release dropped (the grant survives); the variants swapped in the
    /// transport.
    #[test]
    fn a_failed_removal_of_a_listed_connection_is_the_answer_with_nothing_held() {
        rt().block_on(
            a_failed_removal_of_a_listed_connection_is_the_answer_with_nothing_held_case(),
        )
    }

    async fn a_failed_removal_of_a_listed_connection_is_the_answer_with_nothing_held_case() {
        use super::remote_control::{
            create_remote_control_grant, delete_remote_control_grant_records,
            fetch_remote_control_grant, RemoteControlGrant, RemoteControlGrantOutcome,
            INPUT_CLASS_KBM,
        };

        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        for listing_fails in [false, true] {
            let (channel, user, server) = connection_case_ids("RL1");
            let a = format!("{user}:A");
            let other = format!("other{user}");
            let flag = format!("camera:{user}:{server}");
            set_voice_participant_identity(&channel.id, &user, &a)
                .await
                .unwrap();
            conn.set::<_, _, ()>(&flag, true).await.unwrap();
            // The user shares here; `other` controls. The release would end
            // this grant (and try to revoke `other`, which the Reference
            // database cannot recompute, so it escalates to an ejection).
            let grant = RemoteControlGrant {
                id: ulid::Ulid::new().to_string(),
                channel_id: channel.id.clone(),
                server_id: Some(server.clone()),
                node: stub::NODE.to_string(),
                sharer_id: user.clone(),
                controller_id: other.clone(),
                controller_identity: format!("{other}:DEV"),
                input_class: INPUT_CLASS_KBM.to_string(),
            };
            assert_eq!(
                create_remote_control_grant(&grant).await.unwrap(),
                RemoteControlGrantOutcome::Created
            );
            set_channel_node(&channel.id, stub::NODE).await.unwrap();

            let sfu = if listing_fails {
                stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]))
            } else {
                eviction_stub(&[("SID_A", &a)], stub::internal())
            };
            let result = remove_user_from_voice_channel(
                &db,
                &stub::voice_client(sfu.url()),
                &channel,
                &user,
            )
            .await;
            let seen = sfu.finish();

            let kept_grant = fetch_remote_control_grant(&channel.id, &user)
                .await
                .unwrap();
            let mapping = stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap();
            let kept_flag: Option<String> = conn.get(&flag).await.unwrap();
            let member = is_voice_member(&mut conn, &channel, &user).await;

            delete_remote_control_grant_records(&grant)
                .await
                .expect("cleanup");
            delete_voice_participant_identity(&channel.id, &user)
                .await
                .expect("cleanup");
            conn.del::<_, ()>(&flag).await.expect("cleanup");
            delete_channel_node(&channel.id).await.expect("cleanup");

            if listing_fails {
                assert!(result.is_ok(), "control, a failed listing: {result:?}");
                assert_eq!(seen, sfu_requests(&[(stub::LIST, "")]), "control");
                assert_eq!(kept_grant, Some(grant), "control: no release ran");
            } else {
                assert!(
                    matches!(&result, Err(error) if matches!(error.error_type, revolt_result::ErrorType::InternalError)),
                    "a failed removal of a listed connection: {result:?}"
                );
                assert_eq!(
                    seen,
                    sfu_requests(&[
                        (stub::LIST, ""),
                        (stub::REMOVE, &format!("{a}:screen")),
                        (stub::REMOVE, &a),
                        (stub::REMOVE, &grant.controller_identity),
                    ]),
                    "every removal attempted, then the release's ejection of the controller"
                );
                assert_eq!(kept_grant, None, "the release ended the sharer's grant");
            }
            assert_eq!(
                mapping,
                Some(a.clone()),
                "listing fails {listing_fails}: no script ran"
            );
            assert!(
                kept_flag.is_some(),
                "listing fails {listing_fails}: no script ran"
            );
            assert!(
                !member,
                "listing fails {listing_fails}: nothing was created"
            );
        }
    }

    /// P2-6 + RA2-1: a user the SFU does not list, who is not in
    /// `vc_members`, holds no other voice state here and has nothing
    /// recorded, gets NO remote-control release and NO script. Observable:
    /// the SFU sees the listing and nothing else (the release would end the
    /// seeded grant and revoke or eject its controller), the grant is still
    /// stored, and the mapping field and the flag the script would delete
    /// are still there. Mutation b10 (the skip removed) is red on all of it.
    #[test]
    fn a_user_with_nothing_here_gets_no_release_and_no_script() {
        rt().block_on(a_user_with_nothing_here_gets_no_release_and_no_script_case())
    }

    async fn a_user_with_nothing_here_gets_no_release_and_no_script_case() {
        use super::remote_control::{
            create_remote_control_grant, delete_remote_control_grant_records,
            fetch_remote_control_grant, RemoteControlGrant, RemoteControlGrantOutcome,
            INPUT_CLASS_KBM,
        };

        let (channel, user, server) = connection_case_ids("RN1");
        let other = format!("other{user}");
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");
        let flag = format!("camera:{user}:{server}");

        set_channel_node(&channel.id, stub::NODE).await.unwrap();
        set_voice_participant_identity(&channel.id, &user, &user)
            .await
            .unwrap();
        conn.set::<_, _, ()>(&flag, true).await.unwrap();
        let grant = RemoteControlGrant {
            id: ulid::Ulid::new().to_string(),
            channel_id: channel.id.clone(),
            server_id: Some(server.clone()),
            node: stub::NODE.to_string(),
            sharer_id: user.clone(),
            controller_id: other.clone(),
            controller_identity: format!("{other}:DEV"),
            input_class: INPUT_CLASS_KBM.to_string(),
        };
        assert_eq!(
            create_remote_control_grant(&grant).await.unwrap(),
            RemoteControlGrantOutcome::Created
        );

        let sfu = eviction_stub(&[("SID_O", &other)], stub::ok(Vec::new()));
        let result =
            remove_user_from_voice_channel(&db, &stub::voice_client(sfu.url()), &channel, &user)
                .await;
        let seen = sfu.finish();

        let kept_grant = fetch_remote_control_grant(&channel.id, &user)
            .await
            .unwrap();
        let mapping = stored_voice_participant_identity(&channel.id, &user)
            .await
            .unwrap();
        let kept_flag: Option<String> = conn.get(&flag).await.unwrap();

        delete_remote_control_grant_records(&grant)
            .await
            .expect("cleanup");
        delete_voice_participant_identity(&channel.id, &user)
            .await
            .expect("cleanup");
        conn.del::<_, ()>(&flag).await.expect("cleanup");
        delete_channel_node(&channel.id).await.expect("cleanup");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(seen, sfu_requests(&[(stub::LIST, "")]), "the listing only");
        assert_eq!(kept_grant, Some(grant), "no remote-control release ran");
        assert_eq!(mapping, Some(user.clone()), "no script ran");
        assert!(kept_flag.is_some(), "no script ran");
    }

    /// A user WITH voice state and NOTHING recorded (a legacy connection, or
    /// a ghost whose connections are all gone) is still torn down: the set
    /// delete of an empty set is the script's pure survivor check, which
    /// finds no entry and runs the full teardown. Both with no node pinned
    /// (no SFU call at all) and with the room gone at the SFU (one listing).
    #[test]
    fn a_ghost_with_state_and_no_record_is_torn_down() {
        rt().block_on(a_ghost_with_state_and_no_record_is_torn_down_case())
    }

    async fn a_ghost_with_state_and_no_record_is_torn_down_case() {
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        for room_gone in [false, true] {
            let (channel, user, server) = connection_case_ids("RG1");
            create_voice_state(&channel, &user, Timestamp::now_utc())
                .await
                .unwrap();

            let sfu = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::not_found())]));
            if room_gone {
                set_channel_node(&channel.id, stub::NODE).await.unwrap();
            }
            let result = remove_user_from_voice_channel(
                &db,
                &stub::voice_client(sfu.url()),
                &channel,
                &user,
            )
            .await;
            let seen = sfu.finish();

            let member = is_voice_member(&mut conn, &channel, &user).await;
            let left: Vec<Option<String>> =
                conn.mget(per_server_keys(&user, &server)).await.unwrap();
            delete_voice_state(&channel, &user).await.expect("cleanup");
            delete_channel_node(&channel.id).await.expect("cleanup");

            assert!(result.is_ok(), "room gone {room_gone}: {result:?}");
            assert_eq!(
                seen,
                if room_gone {
                    sfu_requests(&[(stub::LIST, "")])
                } else {
                    sfu_requests(&[])
                },
                "room gone {room_gone}"
            );
            assert!(!member, "room gone {room_gone}: the ghost is torn down");
            assert!(
                left.iter().all(Option::is_none),
                "room gone {room_gone}: {left:?}"
            );
        }
    }

    /// WB-2: a failed eviction in a call where Redis holds NOTHING of the
    /// user (no record, no voice state) answers Ok: the failure is reported
    /// and there is nothing to tear down. Two causes, each through the real
    /// function: the SFU answers the ONE listing with a 500, and the pin
    /// names a node missing from the config (UnknownNode before any
    /// network). Nothing is written: the mapping field and the flag the
    /// script would delete are still there. Mutation wb2 (the unconditional
    /// `?`) answers the error.
    #[test]
    fn a_failed_eviction_where_the_user_holds_nothing_answers_ok() {
        rt().block_on(a_failed_eviction_where_the_user_holds_nothing_answers_ok_case())
    }

    async fn a_failed_eviction_where_the_user_holds_nothing_answers_ok_case() {
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        for unknown_node in [false, true] {
            let (channel, user, server) = connection_case_ids("RU1");
            let flag = format!("camera:{user}:{server}");
            set_voice_participant_identity(&channel.id, &user, &user)
                .await
                .unwrap();
            conn.set::<_, _, ()>(&flag, true).await.unwrap();

            let sfu = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]));
            let node = if unknown_node {
                "node-missing-from-config"
            } else {
                stub::NODE
            };
            set_channel_node(&channel.id, node).await.unwrap();
            let result = remove_user_from_voice_channel(
                &db,
                &stub::voice_client(sfu.url()),
                &channel,
                &user,
            )
            .await;
            let seen = sfu.finish();

            let mapping = stored_voice_participant_identity(&channel.id, &user)
                .await
                .unwrap();
            let kept_flag: Option<String> = conn.get(&flag).await.unwrap();

            delete_voice_participant_identity(&channel.id, &user)
                .await
                .expect("cleanup");
            conn.del::<_, ()>(&flag).await.expect("cleanup");
            delete_channel_node(&channel.id).await.expect("cleanup");

            assert!(result.is_ok(), "unknown node {unknown_node}: {result:?}");
            assert_eq!(
                seen,
                if unknown_node {
                    sfu_requests(&[])
                } else {
                    sfu_requests(&[(stub::LIST, "")])
                },
                "unknown node {unknown_node}: the ONE listing and nothing else"
            );
            assert_eq!(
                mapping,
                Some(user.clone()),
                "unknown node {unknown_node}: no script ran"
            );
            assert!(
                kept_flag.is_some(),
                "unknown node {unknown_node}: no script ran"
            );
        }
    }

    /// WB-2's other half: a user who DOES hold something here (a recorded
    /// connection with its state, or the state alone) still gets the error
    /// when the ONE listing fails, with NOTHING torn down: the state, the
    /// membership and any record all stay. Mutation b3 (a held user's error
    /// swallowed into no listing) tears it all down.
    #[test]
    fn a_failed_listing_where_the_user_holds_state_tears_nothing_down() {
        rt().block_on(a_failed_listing_where_the_user_holds_state_tears_nothing_down_case())
    }

    async fn a_failed_listing_where_the_user_holds_state_tears_nothing_down_case() {
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        for recorded in [true, false] {
            let (channel, user, _) = connection_case_ids("RH1");
            if recorded {
                assert!(record_voice_connection(&channel, &user, "SID_H", &user)
                    .await
                    .unwrap());
            }
            create_voice_state(&channel, &user, Timestamp::now_utc())
                .await
                .unwrap();
            set_channel_node(&channel.id, stub::NODE).await.unwrap();

            let sfu = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]));
            let result = remove_user_from_voice_channel(
                &db,
                &stub::voice_client(sfu.url()),
                &channel,
                &user,
            )
            .await;
            let seen = sfu.finish();

            let state = get_voice_state(&channel, &user).await.unwrap();
            let member = is_voice_member(&mut conn, &channel, &user).await;
            let record = recorded_connections(&mut conn, &channel).await;

            delete_voice_state(&channel, &user).await.expect("cleanup");
            delete_channel_node(&channel.id).await.expect("cleanup");

            assert!(
                matches!(&result, Err(error) if matches!(error.error_type, revolt_result::ErrorType::InternalError)),
                "recorded {recorded}: {result:?}"
            );
            assert_eq!(
                seen,
                sfu_requests(&[(stub::LIST, "")]),
                "recorded {recorded}"
            );
            assert!(
                state.is_some(),
                "recorded {recorded}: no teardown after a failed listing"
            );
            assert!(member, "recorded {recorded}");
            let expected: std::collections::BTreeMap<String, String> = if recorded {
                [("SID_H".to_string(), user.clone())].into_iter().collect()
            } else {
                Default::default()
            };
            assert_eq!(record, expected, "recorded {recorded}");
        }
    }

    /// WB-2 through the server walk: two calls, the user in the SECOND only,
    /// the first call's node failing its listing. The walk answers Ok, the
    /// second call is torn down, and the first saw its ONE listing and
    /// nothing else. Mutation wb2 (the unconditional `?`) fails the whole
    /// removal over a call the user was never in: every kick, ban and leave
    /// in the server.
    #[test]
    fn the_server_removal_passes_a_failed_call_the_user_is_not_in() {
        rt().block_on(the_server_removal_passes_a_failed_call_the_user_is_not_in_case())
    }

    async fn the_server_removal_passes_a_failed_call_the_user_is_not_in_case() {
        let (db, mut server, _, _) = sync_fixture("X3").await;
        let suffix = ulid::Ulid::new().to_string();
        let user = format!("userX3{suffix}");
        let elsewhere = UserVoiceChannel {
            id: format!("chanX3a{suffix}"),
            server_id: Some(server.id.clone()),
        };
        let joined = UserVoiceChannel {
            id: format!("chanX3b{suffix}"),
            server_id: Some(server.id.clone()),
        };
        server.channels = vec![elsewhere.id.clone(), joined.id.clone()];
        let mut conn = get_connection().await.expect("redis");

        assert!(record_voice_connection(&joined, &user, "SID2", &user)
            .await
            .unwrap());
        create_voice_state(&joined, &user, Timestamp::now_utc())
            .await
            .unwrap();
        set_channel_node(&elsewhere.id, "node1").await.unwrap();
        set_channel_node(&joined.id, "node2").await.unwrap();

        let failing = stub::Stub::serve(stub::routes(vec![(stub::LIST, stub::internal())]));
        let healthy = eviction_stub(&[("SID2", &user)], stub::ok(Vec::new()));
        let voice_client = stub::voice_client_nodes(
            &[("node1", failing.url()), ("node2", healthy.url())],
            SFU_CALL_TIMEOUT,
            SFU_BREAKER_WINDOW,
        );

        let result = remove_user_from_server_voice(&db, &voice_client, &server, &user).await;
        let (failing_seen, healthy_seen) = (failing.finish(), healthy.finish());

        let joined_member = is_voice_member(&mut conn, &joined, &user).await;
        let joined_record = recorded_connections(&mut conn, &joined).await;
        let left: Vec<Option<String>> =
            conn.mget(per_server_keys(&user, &server.id)).await.unwrap();

        delete_voice_state(&joined, &user).await.expect("cleanup");
        delete_channel_node(&elsewhere.id).await.expect("cleanup");
        delete_channel_node(&joined.id).await.expect("cleanup");

        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            failing_seen,
            sfu_requests(&[(stub::LIST, "")]),
            "the call the user is not in: the ONE listing"
        );
        assert_eq!(
            healthy_seen,
            sfu_requests(&[
                (stub::LIST, ""),
                (stub::REMOVE, &format!("{user}::screen")),
                (stub::REMOVE, &user),
            ]),
            "the call the user is in is still evicted"
        );
        assert!(!joined_member, "the call the user is in is torn down");
        assert!(joined_record.is_empty(), "{joined_record:?}");
        assert!(left.iter().all(Option::is_none), "{left:?}");
    }

    // ---- AFK S-3 WB-8: the Leave no webhook will publish ----

    /// The rule by value: a Leave only on `Last`, and only when no evicted
    /// primary's `participant_left` will announce it. Mutations: the
    /// webhook half dropped (a double Leave), the `Last` half dropped (a
    /// Leave for a user who is still in the call).
    #[test]
    fn a_removal_publishes_the_leave_only_for_an_unannounced_last() {
        use super::removal_publishes_leave;

        assert!(removal_publishes_leave(ConnectionLeave::Last, false));
        assert!(!removal_publishes_leave(ConnectionLeave::Last, true));
        assert!(!removal_publishes_leave(ConnectionLeave::Survivor, false));
        assert!(!removal_publishes_leave(ConnectionLeave::Survivor, true));
    }

    /// Run `removal` and count the `VoiceChannelLeave`s for `user` it
    /// published on `channel`'s topic, through a subscription opened BEFORE
    /// it runs. A marker Leave published after it bounds the read: pub/sub is
    /// FIFO per subscription, so everything the removal published has
    /// arrived once the marker has.
    async fn leaves_published_by<Fut>(
        channel: &UserVoiceChannel,
        user: &str,
        removal: Fut,
    ) -> (Result<()>, usize)
    where
        Fut: std::future::Future<Output = Result<()>>,
    {
        use futures::StreamExt;
        const MARKER: &str = "wb8-marker";

        let mut pubsub = redis_kiss::open_pubsub_connection()
            .await
            .expect("pubsub connection");
        pubsub.subscribe(&channel.id).await.expect("subscribe");

        let result = removal.await;

        EventV1::VoiceChannelLeave {
            id: channel.id.clone(),
            user: MARKER.to_string(),
        }
        .p(channel.id.clone())
        .await;

        let mut leaves = 0;
        let mut stream = pubsub.on_message();
        loop {
            let message = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .expect("the marker Leave must arrive within 5 s")
                .expect("the subscription ended");
            if let Ok(EventV1::VoiceChannelLeave { id, user: left }) =
                redis_kiss::decode_payload::<EventV1>(&message)
            {
                if id != channel.id {
                    continue;
                }
                if left == MARKER {
                    break;
                }
                if left == user {
                    leaves += 1;
                }
            }
        }
        (result, leaves)
    }

    /// WB-8 through the REAL `remove_user_from_voice_channel`: the teardown
    /// publishes exactly one `VoiceChannelLeave` when it answers `Last` and
    /// nothing was evicted (no webhook will follow): a ghost of an ended call
    /// (no node), a room the SFU no longer has, a listing that names nothing
    /// of the user. None when a listed primary was evicted (its
    /// `participant_left` announces it), none on `Survivor` (a sibling
    /// recorded after the removal's read keeps the user in the call), and
    /// none when the user held nothing here. Before WB-8 the first three
    /// published nothing and every other client kept the ghost. Mutations:
    /// the publish removed (the three ghosts are silent); the rule reduced to
    /// `Last` (the evicted case publishes); reduced to "nothing evicted" (the
    /// survivor case publishes).
    #[test]
    fn a_removal_announces_the_leave_no_webhook_will() {
        rt().block_on(a_removal_announces_the_leave_no_webhook_will_case())
    }

    async fn a_removal_announces_the_leave_no_webhook_will_case() {
        let db = Database::Reference(Default::default());
        let mut conn = get_connection().await.expect("redis");

        /// `listing`: `None` = the SFU has no such room, `Some("user")` =
        /// it lists the user's `SID_A`, anything else = it lists another
        /// user only.
        struct Case {
            name: &'static str,
            node: bool,
            listing: Option<&'static str>,
            recorded: bool,
            state: bool,
            late_sibling: bool,
            leaves: usize,
            member_after: bool,
        }
        let cases = [
            Case {
                name: "ghost of an ended call",
                node: false,
                listing: None,
                recorded: true,
                state: true,
                late_sibling: false,
                leaves: 1,
                member_after: false,
            },
            Case {
                name: "room the SFU no longer has",
                node: true,
                listing: None,
                recorded: false,
                state: true,
                late_sibling: false,
                leaves: 1,
                member_after: false,
            },
            Case {
                name: "listing names nothing of the user",
                node: true,
                listing: Some("other"),
                recorded: true,
                state: true,
                late_sibling: false,
                leaves: 1,
                member_after: false,
            },
            Case {
                name: "a listed primary was evicted",
                node: true,
                listing: Some("user"),
                recorded: true,
                state: true,
                late_sibling: false,
                leaves: 0,
                member_after: false,
            },
            Case {
                name: "a sibling recorded after the read survives",
                node: true,
                listing: Some("other"),
                recorded: true,
                state: true,
                late_sibling: true,
                leaves: 0,
                member_after: true,
            },
            Case {
                name: "the user held nothing here",
                node: true,
                listing: Some("other"),
                recorded: false,
                state: false,
                late_sibling: false,
                leaves: 0,
                member_after: false,
            },
        ];

        for case in cases {
            let (channel, user, _) = connection_case_ids("W8");
            let other = format!("other{user}");
            if case.recorded {
                assert!(record_voice_connection(&channel, &user, "SID_A", &user)
                    .await
                    .unwrap());
            }
            if case.state {
                create_voice_state(&channel, &user, Timestamp::now_utc())
                    .await
                    .unwrap();
            }
            if case.node {
                set_channel_node(&channel.id, stub::NODE).await.unwrap();
            }

            let listing = match case.listing {
                None => None,
                Some("user") => Some(stub::list_participants_response_sids(&[(
                    "SID_A", &user, "",
                )])),
                Some(_) => Some(stub::list_participants_response_sids(&[(
                    "SID_O", &other, "",
                )])),
            };
            let sfu = {
                let (channel, user) = (channel.clone(), user.clone());
                let late_sibling = case.late_sibling;
                stub::Stub::serve(move |path, _| match path {
                    stub::LIST => {
                        if late_sibling {
                            // B joins now: after the removal's record read.
                            let _ = rt().block_on(record_voice_connection(
                                &channel,
                                &user,
                                "SID_B",
                                &format!("{user}:B"),
                            ));
                        }
                        match &listing {
                            Some(listing) => stub::ok(listing.clone()),
                            None => stub::not_found(),
                        }
                    }
                    stub::REMOVE => stub::ok(Vec::new()),
                    _ => stub::internal(),
                })
            };

            let voice_client = stub::voice_client(sfu.url());
            let (result, leaves) = leaves_published_by(
                &channel,
                &user,
                remove_user_from_voice_channel(&db, &voice_client, &channel, &user),
            )
            .await;
            sfu.finish();
            let member = is_voice_member(&mut conn, &channel, &user).await;

            delete_voice_state(&channel, &user).await.expect("cleanup");
            delete_channel_node(&channel.id).await.expect("cleanup");

            assert!(result.is_ok(), "{}: {result:?}", case.name);
            assert_eq!(leaves, case.leaves, "{}: Leaves published", case.name);
            assert_eq!(member, case.member_after, "{}: membership after", case.name);
        }
    }

    // A same-server channel switch (a moderator move, or the user hopping
    // channels) whose SFU events arrive out of order: the destination's
    // `participant_joined` is processed BEFORE the source's
    // `participant_left`. The unique key `{user}:{server}` and every state
    // key it scopes are shared by both channels, so the late source leave
    // must leave the destination's live state alone, while the channel-keyed
    // half of that leave still runs in full.
    #[test]
    fn source_leave_after_destination_join_keeps_destination_state() {
        rt().block_on(source_leave_after_destination_join_case())
    }

    async fn source_leave_after_destination_join_case() {
        let suffix = ulid::Ulid::new().to_string();
        let server = format!("srv{suffix}");
        let source = UserVoiceChannel {
            id: format!("chanA{suffix}"),
            server_id: Some(server.clone()),
        };
        let destination = UserVoiceChannel {
            id: format!("chanB{suffix}"),
            server_id: Some(server.clone()),
        };
        let user = format!("user{suffix}");
        let unique_key = format!("{user}:{server}");
        let source_allow = format!("annotations_allow:{}:{}", &source.id, &user);
        let mut conn = get_connection().await.unwrap();

        create_voice_state(&source, &user, Timestamp::now_utc())
            .await
            .expect("join source");
        record_screen_leg(&source.id, &user, "SID_SOURCE")
            .await
            .unwrap();
        let _: () = conn.sadd(&source_allow, "someone").await.unwrap();

        // The destination join lands first and publishes a camera.
        create_voice_state(&destination, &user, Timestamp::now_utc())
            .await
            .expect("join destination");
        update_voice_state_tracks(&destination, &user, true, 1)
            .await
            .unwrap();

        delete_voice_state(&source, &user)
            .await
            .expect("late source leave");

        let state = get_voice_state(&destination, &user)
            .await
            .unwrap()
            .expect("a late source leave must not wipe the destination's voice state");
        assert!(state.camera, "...nor reset its flags");
        assert_eq!(
            get_user_voice_channel_in_server(&user, &server)
                .await
                .unwrap()
                .as_deref(),
            Some(destination.id.as_str()),
            "...nor drop the unique key's channel mapping"
        );
        let scoped: Vec<Option<String>> = conn.mget(voice_state_keys(&unique_key)).await.unwrap();
        assert!(
            scoped.iter().all(Option::is_some),
            "every destination-scoped key survives: {scoped:?}"
        );

        // The channel-keyed half of the source leave still ran.
        assert!(!is_in_voice_channel(&user, &source).await.unwrap());
        assert!(get_voice_channel_members(&source).await.unwrap().is_none());
        assert!(get_screen_leg_sid(&source.id, &user)
            .await
            .unwrap()
            .is_none());
        let allow_exists: bool = conn.exists(&source_allow).await.unwrap();
        assert!(
            !allow_exists,
            "the source's draw consent dies with the leave"
        );
        assert!(is_in_voice_channel(&user, &destination).await.unwrap());
        assert_eq!(
            get_voice_channel_members(&destination).await.unwrap(),
            Some(vec![user.clone()])
        );

        // The destination's own leave owns the state and removes all of it.
        delete_voice_state(&destination, &user)
            .await
            .expect("destination leave");
        assert!(get_voice_state(&destination, &user)
            .await
            .unwrap()
            .is_none());
        assert!(get_user_voice_channel_in_server(&user, &server)
            .await
            .unwrap()
            .is_none());
        let scoped: Vec<Option<String>> = conn.mget(voice_state_keys(&unique_key)).await.unwrap();
        assert!(
            scoped.iter().all(Option::is_none),
            "every scoped key is gone: {scoped:?}"
        );
        assert!(!is_in_voice_channel(&user, &destination).await.unwrap());

        // No unique key at all: nothing claims the scoped keys, so any leave
        // still clears strays (the pre-guard behaviour, which the reconcile
        // sweep's leaves rely on).
        let _: () = conn
            .set(format!("recording:{unique_key}"), true)
            .await
            .unwrap();
        delete_voice_state(&source, &user)
            .await
            .expect("stray cleanup");
        let stray: Option<bool> = conn.get(format!("recording:{unique_key}")).await.unwrap();
        assert!(stray.is_none(), "an unclaimed stray key is still cleared");
    }

    // The session record a move is delivered to (media-e2ee final audit F1),
    // and why no leave drops it (lane 6a3): livekit's full reconnect rejoins
    // with the same token and never calls `join_call`, so the record has to
    // outlive the leave that comes with it. The seat kind is recorded with
    // the session (merge slice RRB-1) and read back with it.
    #[test]
    fn voice_session_record_lifecycle_survives_a_reconnect() {
        rt().block_on(voice_session_record_case())
    }

    async fn voice_session_record_case() {
        let suffix = ulid::Ulid::new().to_string();
        let channel = UserVoiceChannel {
            id: format!("chan{suffix}"),
            server_id: Some(format!("srv{suffix}")),
        };
        let user = format!("user{suffix}");
        let key = voice_session_key(&channel.id);
        assert_eq!(key, format!("voice_session:{}", &channel.id));
        let mut conn = get_connection().await.unwrap();

        assert_eq!(
            get_voice_participant_session(&channel.id, &user)
                .await
                .unwrap(),
            None,
            "no record: the owner is unknown"
        );
        assert_eq!(
            get_voice_participant_session_seat(&channel.id, &user)
                .await
                .unwrap(),
            None
        );

        // The desktop joins as its device D1; the record names it at once.
        set_voice_participant_session(&channel.id, &user, "DESKTOP", Some("D1"))
            .await
            .unwrap();
        assert_eq!(
            get_voice_participant_session(&channel.id, &user)
                .await
                .unwrap()
                .as_deref(),
            Some("DESKTOP")
        );
        assert_eq!(
            get_voice_participant_session_seat(&channel.id, &user)
                .await
                .unwrap(),
            Some(("DESKTOP".to_string(), SeatKind::Device("D1".to_string())))
        );
        let stored: Option<String> = conn.hget(&key, &user).await.unwrap();
        assert_eq!(stored.as_deref(), Some("DESKTOP|d:D1"));

        // A reconnect: the participant leaves and rejoins on the same token.
        // The leave is a per-user voice-state delete and nothing else touches
        // the record, so it still names the desktop for the rejoin.
        delete_voice_state(&channel, &user)
            .await
            .expect("the reconnect's leave");
        assert_eq!(
            get_voice_participant_session_seat(&channel.id, &user)
                .await
                .unwrap(),
            Some(("DESKTOP".to_string(), SeatKind::Device("D1".to_string()))),
            "a leave must not take the record with it"
        );

        // The web session joins bare; its record replaces the desktop's.
        set_voice_participant_session(&channel.id, &user, "WEB", None)
            .await
            .unwrap();
        assert_eq!(
            get_voice_participant_session(&channel.id, &user)
                .await
                .unwrap()
                .as_deref(),
            Some("WEB"),
            "the newest join owns the participant"
        );
        assert_eq!(
            get_voice_participant_session_seat(&channel.id, &user)
                .await
                .unwrap(),
            Some(("WEB".to_string(), SeatKind::Bare)),
            "and its seat kind replaces the desktop's"
        );

        // The owner re-check compares the SESSION part only, whatever seat
        // kind it was recorded with.
        for (device, seat) in [
            (None, SeatKind::Bare),
            (Some("D1"), SeatKind::Device("D1".to_string())),
        ] {
            set_voice_participant_session(&channel.id, &user, "WEB", device)
                .await
                .unwrap();
            assert!(
                voice_participant_session_is(&channel.id, &user, Some("WEB"))
                    .await
                    .unwrap(),
                "{seat:?}: the session part matches"
            );
            for other in [
                None,
                Some("WE"),
                Some("WEBX"),
                Some("WEB|b"),
                Some("WEB|d:D1"),
            ] {
                assert!(
                    !voice_participant_session_is(&channel.id, &user, other)
                        .await
                        .unwrap(),
                    "{seat:?}: `{other:?}` must not match a record naming WEB"
                );
            }
        }
        // A legacy record (the session alone, from before the seat kind)
        // still names its session, with the seat kind unknown.
        let _: () = conn.hset(&key, &user, "WEB").await.unwrap();
        assert!(
            voice_participant_session_is(&channel.id, &user, Some("WEB"))
                .await
                .unwrap()
        );
        assert_eq!(
            get_voice_participant_session_seat(&channel.id, &user)
                .await
                .unwrap(),
            Some(("WEB".to_string(), SeatKind::Unknown))
        );

        // A `force_disconnect` kick from a join elsewhere drops this user's
        // record, and nobody else's (lane 6a4).
        let other = format!("other{suffix}");
        set_voice_participant_session(&channel.id, &other, "OTHER", None)
            .await
            .unwrap();
        drop_voice_participant_session(&channel.id, &user)
            .await
            .expect("the kick's drop");
        assert_eq!(
            get_voice_participant_session(&channel.id, &user)
                .await
                .unwrap(),
            None,
            "a kick must take the kicked user's record with it"
        );
        assert!(
            !voice_participant_session_is(&channel.id, &user, Some("WEB"))
                .await
                .unwrap(),
            "a move planned for the kicked session no longer matches"
        );
        assert_eq!(
            get_voice_participant_session(&channel.id, &other)
                .await
                .unwrap()
                .as_deref(),
            Some("OTHER"),
            "another user's record in the same call stays"
        );
        set_voice_participant_session(&channel.id, &user, "WEB", None)
            .await
            .unwrap();

        // An empty session, never written by a route, reads as no record,
        // whatever seat it was written with.
        for device in [None, Some("D1")] {
            set_voice_participant_session(&channel.id, &user, "", device)
                .await
                .unwrap();
            assert_eq!(
                get_voice_participant_session(&channel.id, &user)
                    .await
                    .unwrap(),
                None,
                "an empty record must not resolve to a session ({device:?})"
            );
        }

        // An empty device id records the seat as unknown, never as a device
        // or bare; a session id holding the separator is refused, with
        // nothing written.
        set_voice_participant_session(&channel.id, &user, "WEB", Some(""))
            .await
            .unwrap();
        assert_eq!(
            get_voice_participant_session_seat(&channel.id, &user)
                .await
                .unwrap(),
            Some(("WEB".to_string(), SeatKind::Unknown))
        );
        assert!(
            set_voice_participant_session(&channel.id, &user, "EVIL|b", Some("D1"))
                .await
                .is_err(),
            "a session id with the separator is never recorded"
        );
        let stored: Option<String> = conn.hget(&key, &user).await.unwrap();
        assert_eq!(stored.as_deref(), Some("WEB"), "nothing was written");

        // The whole hash goes with the call (room_finished, the reconcile
        // sweep, channel delete).
        set_voice_participant_session(&channel.id, &user, "WEB", None)
            .await
            .unwrap();
        delete_channel_voice_state(&channel, &[])
            .await
            .expect("call teardown");
        let exists: bool = conn.exists(&key).await.unwrap();
        assert!(!exists, "the session hash must not outlive the call");
    }

    // A move carries the source record over only while the source still
    // holds the record the move read (lane 6a3; merge slice RRB-1: the
    // session AND its seat kind): a join from another session in between,
    // or the same session rejoining as another kind of seat, must refuse the
    // move, not hand the destination to the session that join kicked or
    // record a seat the move did not mint for. The destination gets the
    // whole record, seat kind included (control CARRY-NOSEAT).
    #[test]
    fn a_move_carries_the_session_record_only_while_the_source_names_it() {
        rt().block_on(carry_voice_session_case())
    }

    async fn carry_voice_session_case() {
        let suffix = ulid::Ulid::new().to_string();
        let source = format!("src{suffix}");
        let destination = format!("dst{suffix}");
        let fresh = format!("fresh{suffix}");
        let gone = format!("gone{suffix}");
        let user = format!("user{suffix}");
        let d1 = SeatKind::Device("D1".to_string());

        // The compare on its own.
        assert!(
            voice_participant_session_is(&source, &user, None)
                .await
                .unwrap(),
            "no record matches `None`"
        );
        assert!(
            !voice_participant_session_is(&source, &user, Some("DESKTOP"))
                .await
                .unwrap()
        );
        set_voice_participant_session(&source, &user, "DESKTOP", Some("D1"))
            .await
            .unwrap();
        assert!(
            voice_participant_session_is(&source, &user, Some("DESKTOP"))
                .await
                .unwrap()
        );
        for other in [None, Some("WEB"), Some(""), Some("DESKTOPX"), Some("DESK")] {
            assert!(
                !voice_participant_session_is(&source, &user, other)
                    .await
                    .unwrap(),
                "`{other:?}` must not match a record naming DESKTOP"
            );
        }

        // Match: carried with its seat kind, and the source is left as it
        // was.
        assert!(
            carry_voice_participant_session(&source, &destination, &user, "DESKTOP", &d1)
                .await
                .unwrap(),
            "the source still holds the record: carried"
        );
        assert_eq!(
            get_voice_participant_session_seat(&destination, &user)
                .await
                .unwrap(),
            Some(("DESKTOP".to_string(), d1.clone())),
            "the destination records the same session AND seat kind"
        );
        assert_eq!(
            get_voice_participant_session_seat(&source, &user)
                .await
                .unwrap(),
            Some(("DESKTOP".to_string(), d1.clone())),
            "the source record stays until the participant is gone"
        );

        // The same session, but the move read another seat kind than the
        // source now holds: refused, the destination keeps what it had.
        for read in [
            SeatKind::Bare,
            SeatKind::Unknown,
            SeatKind::Device("D2".to_string()),
        ] {
            assert!(
                !carry_voice_participant_session(&source, &fresh, &user, "DESKTOP", &read)
                    .await
                    .unwrap(),
                "{read:?}: the source holds DESKTOP seated as D1, not this"
            );
        }
        assert_eq!(
            get_voice_participant_session(&fresh, &user).await.unwrap(),
            None
        );

        // Bare and legacy records are carried as they are.
        set_voice_participant_session(&source, &user, "DESKTOP", None)
            .await
            .unwrap();
        assert!(carry_voice_participant_session(
            &source,
            &destination,
            &user,
            "DESKTOP",
            &SeatKind::Bare
        )
        .await
        .unwrap());
        assert_eq!(
            get_voice_participant_session_seat(&destination, &user)
                .await
                .unwrap(),
            Some(("DESKTOP".to_string(), SeatKind::Bare))
        );
        let mut conn = get_connection().await.unwrap();
        let _: () = conn
            .hset(voice_session_key(&source), &user, "DESKTOP")
            .await
            .unwrap();
        assert!(carry_voice_participant_session(
            &source,
            &destination,
            &user,
            "DESKTOP",
            &SeatKind::Unknown
        )
        .await
        .unwrap());
        assert_eq!(
            get_voice_participant_session_seat(&destination, &user)
                .await
                .unwrap(),
            Some(("DESKTOP".to_string(), SeatKind::Unknown)),
            "a legacy record stays unknown where it is carried"
        );

        // Mismatch: the web session joined the source after the move read
        // it. Nothing is carried, and the destination keeps what it had.
        set_voice_participant_session(&source, &user, "WEB", None)
            .await
            .unwrap();
        set_voice_participant_session(&destination, &user, "EARLIER", None)
            .await
            .unwrap();
        for read in [SeatKind::Bare, SeatKind::Unknown, d1.clone()] {
            assert!(
                !carry_voice_participant_session(&source, &destination, &user, "DESKTOP", &read)
                    .await
                    .unwrap(),
                "the source names another session: refused ({read:?})"
            );
        }
        assert_eq!(
            get_voice_participant_session(&destination, &user)
                .await
                .unwrap()
                .as_deref(),
            Some("EARLIER")
        );
        assert_eq!(
            get_voice_participant_session(&source, &user)
                .await
                .unwrap()
                .as_deref(),
            Some("WEB")
        );

        // An empty session id, a session id holding the separator, or a
        // source with no record: never carried.
        assert!(
            !carry_voice_participant_session(&source, &fresh, &user, "", &SeatKind::Unknown)
                .await
                .unwrap(),
            "an empty session id is never carried"
        );
        set_voice_participant_session(&source, &user, "WEB", None)
            .await
            .unwrap();
        assert!(
            !carry_voice_participant_session(&source, &fresh, &user, "WEB|b", &SeatKind::Unknown)
                .await
                .unwrap(),
            "a session id holding the separator is never carried"
        );
        assert!(
            !carry_voice_participant_session(&gone, &fresh, &user, "DESKTOP", &d1)
                .await
                .unwrap(),
            "a source with no record carries nothing"
        );
        assert_eq!(
            get_voice_participant_session(&fresh, &user).await.unwrap(),
            None
        );

        for channel in [&source, &destination] {
            delete_channel_voice_state(
                &UserVoiceChannel {
                    id: channel.clone(),
                    server_id: None,
                },
                &[],
            )
            .await
            .expect("cleanup");
        }
    }

    // ---- merge slice F15: the merged move, end to end on the SFU stub ----
    //
    // The REAL `move_user_to_voice_channel_expecting` against Redis, the
    // Reference database and the loopback SFU stub, with a Redis
    // subscription on the owner's session topic AND the user's own topic
    // (`{user}!`, which every session of the user reads), so where the move
    // event goes is observed rather than inferred.
    //
    // The stub is registered under a node name the test configuration's
    // `hosts.livekit` already has (the move resolves the destination's public
    // URL there and refuses an unknown node before any write). The plan named
    // `overwrite_config` for this (P2A-12); it is not usable here: it is
    // behind revolt-config's `test` feature, which this crate's tests do not
    // enable, and it may run only once per process, which a `cargo test` of
    // this crate is.

    /// A node the test configuration serves a public URL for.
    async fn configured_node() -> (String, String) {
        config()
            .await
            .hosts
            .livekit
            .iter()
            .min()
            .map(|(node, url)| (node.clone(), url.clone()))
            .expect("the test configuration has no `hosts.livekit` node")
    }

    struct MoveCase {
        db: Database,
        server: Server,
        source: Channel,
        destination: Channel,
        target: User,
        node: String,
        url: String,
    }

    impl MoveCase {
        fn source_uvc(&self) -> UserVoiceChannel {
            UserVoiceChannel::from_channel(&self.source)
        }

        fn destination_uvc(&self) -> UserVoiceChannel {
            UserVoiceChannel::from_channel(&self.destination)
        }

        /// A `VoiceClient` whose one node, the configured one, is `sfu`.
        fn voice_client(&self, sfu: &stub::Stub) -> VoiceClient {
            stub::voice_client_nodes(
                &[(self.node.as_str(), sfu.url())],
                SFU_CALL_TIMEOUT,
                SFU_BREAKER_WINDOW,
            )
        }

        /// Put the target in the source call on the configured node, owned
        /// by `session` when there is one, recorded as `join_call` records
        /// it: seated as `device`, or bare when `None` (merge slice RRB-1).
        async fn connect(&self, session: Option<&str>, device: Option<&str>) {
            create_voice_state(&self.source_uvc(), &self.target.id, Timestamp::now_utc())
                .await
                .unwrap();
            set_channel_node(self.source.id(), &self.node).await.unwrap();
            if let Some(session) = session {
                set_voice_participant_session(self.source.id(), &self.target.id, session, device)
                    .await
                    .unwrap();
            }
        }

        /// Deny Connect (and nothing else) to everyone but the owner on the
        /// destination.
        async fn deny_connect_on_destination(&mut self) {
            use crate::PartialChannel;
            use revolt_permissions::OverrideField;

            self.destination
                .update(
                    &self.db,
                    PartialChannel {
                        default_permissions: Some(OverrideField {
                            a: 0,
                            d: ChannelPermission::Connect as i64,
                        }),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("channel override");
        }

        /// Set everyone's destination override to allow `allow` and deny
        /// `deny` (bits of `ChannelPermission`).
        async fn override_destination(&mut self, allow: i64, deny: i64) {
            use crate::PartialChannel;
            use revolt_permissions::OverrideField;

            self.destination
                .update(
                    &self.db,
                    PartialChannel {
                        default_permissions: Some(OverrideField { a: allow, d: deny }),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("channel override");
        }

        /// Cap the destination at `max_users` and seat `occupants` other
        /// users in its roster. Returns them, for [`Self::empty_destination`].
        async fn fill_destination(&mut self, max_users: usize, occupants: usize) -> Vec<String> {
            use crate::{PartialChannel, VoiceInformation};

            self.destination
                .update(
                    &self.db,
                    PartialChannel {
                        voice: Some(VoiceInformation {
                            max_users: Some(max_users),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    vec![],
                )
                .await
                .expect("the cap");
            let mut seated = Vec::new();
            for n in 0..occupants {
                let occupant = format!("F15Occupant{n}{}", self.target.id);
                create_voice_state(&self.destination_uvc(), &occupant, Timestamp::now_utc())
                    .await
                    .unwrap();
                seated.push(occupant);
            }
            seated
        }

        async fn empty_destination(&self, occupants: &[String]) {
            for occupant in occupants {
                delete_voice_state(&self.destination_uvc(), occupant)
                    .await
                    .expect("cleanup");
            }
        }

        async fn move_now(
            &self,
            voice_client: &VoiceClient,
            session: Option<&str>,
            policy: MovePolicy<'_>,
        ) -> Result<VoiceMoveOutcome> {
            move_user_to_voice_channel_expecting(
                &self.db,
                voice_client,
                &self.target,
                &self.destination,
                self.source.id(),
                session,
                policy,
            )
            .await
        }

        async fn cleanup(&self) {
            let mut conn = get_connection().await.expect("redis");
            let _: () = conn
                .del(&[
                    move_admission_key(&self.target.id, self.destination.id()),
                    format!("moved_to:{}:{}", self.target.id, self.destination.id()),
                ])
                .await
                .expect("cleanup");
            delete_voice_state(&self.source_uvc(), &self.target.id)
                .await
                .expect("cleanup");
            for uvc in [self.source_uvc(), self.destination_uvc()] {
                delete_channel_voice_state(&uvc, &[]).await.expect("cleanup");
                delete_channel_node(&uvc.id).await.expect("cleanup");
            }
        }
    }

    /// A session id no other test uses: the tests run concurrently, and a
    /// session topic shared between two of them lets one's move event
    /// reach the other's subscription.
    fn unique_session(tag: &str, case: &MoveCase) -> String {
        format!("F15{tag}{}", case.target.id)
    }

    /// A server with a source and a destination voice channel and one
    /// member, in a fresh Reference database.
    async fn move_case(tag: &str) -> MoveCase {
        use crate::Member;
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };

        let (node, url) = configured_node().await;
        let db = Database::Reference(Default::default());
        let owner = User::create(&db, format!("F15Owner{tag}"), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: format!("F15Server{tag}"),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;
        let mut channels = Vec::new();
        for name in ["Source", "Destination"] {
            channels.push(
                Channel::create_server_channel(
                    &db,
                    &mut server,
                    DataCreateServerChannel {
                        channel_type: LegacyServerChannelType::Voice,
                        name: name.to_string(),
                        ..Default::default()
                    },
                    true,
                )
                .await
                .expect("`Channel`"),
            );
        }
        let destination = channels.pop().expect("destination");
        let source = channels.pop().expect("source");
        let target = User::create(&db, format!("F15Target{tag}"), None, None)
            .await
            .expect("`User`");
        Member::create(&db, &server, &target, None)
            .await
            .expect("`Member`");

        MoveCase {
            db,
            server,
            source,
            destination,
            target,
            node,
            url,
        }
    }

    /// An SFU stub listing `(identity, conn nonce)` for the source and
    /// answering `CreateRoom` and `RemoveParticipant` with a 200.
    fn move_stub(listing: &[(&str, &str)]) -> stub::Stub {
        stub::Stub::serve(stub::routes(vec![
            (stub::LIST, stub::ok(stub::list_participants_response(listing))),
            (stub::CREATE_ROOM, stub::ok(Vec::new())),
            (stub::REMOVE, stub::ok(Vec::new())),
        ]))
    }

    /// An E2EE identity row for `device_id`, bound to `last_session_id`.
    fn identity_row(user_id: &str, device_id: &str, last_session_id: &str) -> crate::E2EEIdentity {
        crate::E2EEIdentity {
            id: format!("{user_id}:{device_id}"),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            protocol_version: 1,
            ed25519_key: "ed25519".to_string(),
            curve25519_key: "curve25519".to_string(),
            signature: "signature".to_string(),
            fallback_key: crate::E2EESignedKey {
                key_id: "fallback0".to_string(),
                key: "key".to_string(),
                signature: "signature".to_string(),
            },
            previous_fallback_key: None,
            created_at: Timestamp::now_utc(),
            last_seen_at: Timestamp::now_utc(),
            last_session_id: last_session_id.to_string(),
        }
    }

    /// Run `moving` with a subscription on `session:{session}` and on
    /// `{user}!` opened BEFORE it, and return every `UserMoveVoiceChannel`
    /// each topic carried. A marker published on each topic afterwards
    /// bounds the read: pub/sub is FIFO per subscription.
    async fn moves_published_by<Fut>(
        user: &str,
        session: &str,
        moving: Fut,
    ) -> (Result<VoiceMoveOutcome>, Vec<EventV1>, Vec<EventV1>)
    where
        Fut: std::future::Future<Output = Result<VoiceMoveOutcome>>,
    {
        use crate::events::client::session_topic;
        use futures::StreamExt;
        const MARKER: &str = "f15-marker";

        let session_topic = session_topic(session);
        let user_topic = format!("{user}!");
        let mut pubsub = redis_kiss::open_pubsub_connection()
            .await
            .expect("pubsub connection");
        pubsub.subscribe(&session_topic).await.expect("subscribe");
        pubsub.subscribe(&user_topic).await.expect("subscribe");

        let result = moving.await;

        for topic in [&session_topic, &user_topic] {
            EventV1::VoiceChannelLeave {
                id: topic.clone(),
                user: MARKER.to_string(),
            }
            .p(topic.clone())
            .await;
        }

        let (mut on_session, mut on_user) = (Vec::new(), Vec::new());
        let mut markers = 0;
        let mut stream = pubsub.on_message();
        while markers < 2 {
            let message = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
                .await
                .expect("both markers must arrive within 5 s")
                .expect("the subscription ended");
            let channel = message.get_channel_name().to_string();
            match redis_kiss::decode_payload::<EventV1>(&message) {
                Ok(EventV1::VoiceChannelLeave { user: marker, .. }) if marker == MARKER => {
                    markers += 1
                }
                Ok(event @ EventV1::UserMoveVoiceChannel { .. }) => {
                    if channel == session_topic {
                        on_session.push(event);
                    } else {
                        on_user.push(event);
                    }
                }
                _ => {}
            }
        }
        (result, on_session, on_user)
    }

    fn requested(seen: &[(String, String)], path: &str) -> Vec<String> {
        seen.iter()
            .filter(|(seen_path, _)| seen_path == path)
            .map(|(_, identity)| identity.clone())
            .collect()
    }

    /// F15 Session, and voice-move RT-7's delivery test ported onto the
    /// merged move: the move event reaches ONLY the session recorded in the
    /// source, never the user's own topic. Two seats:
    ///
    /// - a device seat bound to the owning session, which it was recorded as
    ///   joining with: a token for that device, and the event names the
    ///   connection (`device_id`, `conn_nonce`: F12, proven the owner's);
    /// - a bare seat, recorded as bare: a bare token, and the event names
    ///   nothing (a bare seat cannot be proven the owner's; the client acts
    ///   on "connected to `from`").
    ///
    /// Either way the destination records the owner with the same seat kind
    /// (merge slice RRB-1; control CARRY-NOSEAT).
    ///
    /// Control D (`.private_session(` back to `.private(target.id.clone())`)
    /// moves the event to the user topic and fails here.
    #[test]
    fn a_move_is_delivered_to_the_session_recorded_in_the_source_channel() {
        rt().block_on(a_move_is_delivered_to_the_session_recorded_in_the_source_channel_case())
    }

    async fn a_move_is_delivered_to_the_session_recorded_in_the_source_channel_case() {
        for device in [Some("D1"), None] {
            let case = move_case("S").await;
            let owner = unique_session("OWNER", &case);
            let owner = owner.as_str();
            let identity = move_token_identity(&case.target.id, device);
            if let Some(device) = device {
                case.db
                    .insert_e2ee_identity(&identity_row(&case.target.id, device, owner))
                    .await
                    .expect("identity row");
            }
            case.connect(Some(owner), device).await;
            let sfu = move_stub(&[(identity.as_str(), "N-OWNED")]);
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                owner,
                case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
            )
            .await;
            let seen = sfu.finish();
            let carried = get_voice_participant_session(case.destination.id(), &case.target.id)
                .await
                .unwrap();
            let carried_seat =
                get_voice_participant_session_seat(case.destination.id(), &case.target.id)
                    .await
                    .unwrap()
                    .map(|(_, seat)| seat);
            let admission = peek_move_admission(&case.target.id, case.destination.id())
                .await
                .unwrap();
            let marker = get_user_moved_to_voice(case.destination.id(), &case.target.id)
                .await
                .unwrap();
            case.cleanup().await;

            assert_eq!(
                result.expect("the move"),
                VoiceMoveOutcome::Moved {
                    node: case.node.clone(),
                    from: case.source.id().to_string(),
                },
                "{device:?}"
            );
            assert!(on_user.is_empty(), "{device:?}: nothing on the user topic: {on_user:?}");
            assert_eq!(on_session.len(), 1, "{device:?}: {on_session:?}");
            let EventV1::UserMoveVoiceChannel {
                node,
                url,
                device_id,
                conn_nonce,
                from,
                to,
                token,
            } = on_session[0].clone()
            else {
                unreachable!()
            };
            assert_eq!(node, case.node);
            assert_eq!(url.as_deref(), Some(case.url.as_str()), "the node's public URL");
            assert_eq!((from.as_str(), to.as_str()), (case.source.id(), case.destination.id()));
            assert_eq!(device_id.as_deref(), device, "addressing only when proven");
            assert_eq!(
                conn_nonce.as_deref(),
                device.map(|_| "N-OWNED"),
                "the nonce only when the connection is proven the owner's"
            );
            let token = token.expect("a session delivery carries a token");
            let claims = livekit_api::access_token::Claims::from_unverified(&token)
                .expect("decode token");
            assert_eq!(claims.sub, identity, "minted for the chosen seat's identity");

            assert_eq!(carried.as_deref(), Some(owner), "the owner is carried over");
            assert_eq!(
                carried_seat,
                Some(device.map_or(SeatKind::Bare, |device| {
                    SeatKind::Device(device.to_string())
                })),
                "with the seat kind it was recorded with"
            );
            assert_eq!(admission, None, "a target with Connect needs no admission");
            assert!(marker.is_some(), "the Join label is written");
            assert_eq!(requested(&seen, stub::CREATE_ROOM).len(), 1, "{seen:?}");
            assert!(
                requested(&seen, stub::REMOVE).contains(&identity),
                "the moved connection is evicted from the source: {seen:?}"
            );
        }
    }

    /// F15 SessionNoToken, B2: the owner recorded as seated as device D1,
    /// whose identity row is bound to ANOTHER session than the owner (a
    /// device re-bound since the join). The owner is told, with no token and
    /// no addressing; its client joins through `join_call`, which checks the
    /// binding. Control TOKEN-ALWAYS (a token for every delivery) fails here.
    #[test]
    fn a_tokenless_move_reaches_the_owner_without_a_token() {
        rt().block_on(a_tokenless_move_reaches_the_owner_without_a_token_case())
    }

    async fn a_tokenless_move_reaches_the_owner_without_a_token_case() {
        let case = move_case("T").await;
        let owner = unique_session("WEB", &case);
        let owner = owner.as_str();
        let identity = format!("{}:D1", case.target.id);
        case.db
            .insert_e2ee_identity(&identity_row(&case.target.id, "D1", "F15DESKTOP"))
            .await
            .expect("identity row");
        case.connect(Some(owner), Some("D1")).await;
        let sfu = move_stub(&[(identity.as_str(), "N-D1")]);
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        let seen = sfu.finish();
        let carried = get_voice_participant_session(case.destination.id(), &case.target.id)
            .await
            .unwrap();
        case.cleanup().await;

        assert!(
            matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
            "{result:?}"
        );
        assert!(on_user.is_empty(), "{on_user:?}");
        assert_eq!(on_session.len(), 1, "{on_session:?}");
        let EventV1::UserMoveVoiceChannel {
            url,
            device_id,
            conn_nonce,
            token,
            ..
        } = on_session[0].clone()
        else {
            unreachable!()
        };
        assert_eq!(token, None, "no token for a session the device is not bound to");
        assert_eq!((device_id, conn_nonce), (None, None), "and no addressing");
        assert_eq!(url.as_deref(), Some(case.url.as_str()));
        assert_eq!(carried.as_deref(), Some(owner));
        assert_eq!(requested(&seen, stub::CREATE_ROOM).len(), 1, "{seen:?}");
    }

    /// F15 Nobody, and voice-move red #9 ported onto the merged move: with
    /// no recorded owner nobody can be told, so a moderator's move is the
    /// disconnect it amounts to. Nothing is published anywhere, no room is
    /// created, no node pinned, no session carried, no label or admission
    /// written, and every listed connection is evicted from the source.
    #[test]
    fn a_move_nobody_can_be_told_about_is_a_disconnect() {
        rt().block_on(a_move_nobody_can_be_told_about_is_a_disconnect_case())
    }

    async fn a_move_nobody_can_be_told_about_is_a_disconnect_case() {
        let case = move_case("N").await;
        case.connect(None, None).await;
        let sfu = move_stub(&[(case.target.id.as_str(), "N-BARE")]);
        let voice_client = case.voice_client(&sfu);

        // Nothing may reach any session: `moves_published_by` watches the
        // user topic, and a session topic nobody was told about.
        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            &unique_session("NOBODY", &case),
            case.move_now(&voice_client, None, MovePolicy::Moderator),
        )
        .await;
        let seen = sfu.finish();
        let node = get_channel_node(case.destination.id()).await.unwrap();
        let carried = get_voice_participant_session(case.destination.id(), &case.target.id)
            .await
            .unwrap();
        let marker = get_user_moved_to_voice(case.destination.id(), &case.target.id)
            .await
            .unwrap();
        let admission = peek_move_admission(&case.target.id, case.destination.id())
            .await
            .unwrap();
        case.cleanup().await;

        assert_eq!(result.expect("the disconnect"), VoiceMoveOutcome::Disconnected);
        assert!(on_session.is_empty() && on_user.is_empty(), "{on_session:?} {on_user:?}");
        assert!(requested(&seen, stub::CREATE_ROOM).is_empty(), "no room: {seen:?}");
        assert_eq!(requested(&seen, stub::LIST).len(), 1, "{seen:?}");
        assert!(
            requested(&seen, stub::REMOVE).contains(&case.target.id),
            "the participant is evicted: {seen:?}"
        );
        assert_eq!(node, None, "no destination node is pinned");
        assert_eq!(carried, None, "no session is carried");
        assert_eq!(marker, None, "no Join label");
        assert_eq!(admission, None, "no admission");
    }

    /// Merge slice P2A-3, behaviorally: the tokenless delivery of the case
    /// above, into a destination the target cannot Connect to, is refused
    /// before anything is written or asked of the SFU beyond the listing.
    #[test]
    fn a_tokenless_move_without_connect_is_refused() {
        rt().block_on(a_tokenless_move_without_connect_is_refused_case())
    }

    async fn a_tokenless_move_without_connect_is_refused_case() {
        let mut case = move_case("R").await;
        let owner = unique_session("WEB", &case);
        let owner = owner.as_str();
        case.deny_connect_on_destination().await;
        let identity = format!("{}:D1", case.target.id);
        case.db
            .insert_e2ee_identity(&identity_row(&case.target.id, "D1", "F15DESKTOP"))
            .await
            .expect("identity row");
        case.connect(Some(owner), Some("D1")).await;
        let sfu = move_stub(&[(identity.as_str(), "N-D1")]);
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        let seen = sfu.finish();
        let node = get_channel_node(case.destination.id()).await.unwrap();
        let carried = get_voice_participant_session(case.destination.id(), &case.target.id)
            .await
            .unwrap();
        case.cleanup().await;

        assert_eq!(
            result.expect("an outcome, not an error"),
            VoiceMoveOutcome::TargetCannotJoin
        );
        assert!(on_session.is_empty() && on_user.is_empty());
        assert_eq!(
            seen,
            sfu_requests(&[(stub::LIST, "")]),
            "nothing but the listing"
        );
        assert_eq!((node, carried), (None, None), "nothing written");
    }

    /// Merge slice F4/F5 (voice-move red #4, behaviorally): a `join_call`
    /// from another session lands between the carry-over and the
    /// announcement (simulated at the room creation, which follows the
    /// carry). The re-check sees the source record no longer naming the
    /// planned owner and refuses: nothing announced, labelled, admitted or
    /// evicted. Controls RECHECK (the re-check deleted) and CAS (its refusal
    /// dropped, the carry trusted as atomic) publish the event to the kicked
    /// session and fail here.
    #[test]
    fn a_join_after_the_carry_refuses_the_move_before_the_event() {
        rt().block_on(a_join_after_the_carry_refuses_the_move_before_the_event_case())
    }

    async fn a_join_after_the_carry_refuses_the_move_before_the_event_case() {
        let mut case = move_case("K").await;
        let owner = unique_session("DESKTOP", &case);
        let owner = owner.as_str();
        case.deny_connect_on_destination().await;
        case.connect(Some(owner), None).await;
        let sfu = {
            let listing =
                stub::list_participants_response(&[(case.target.id.as_str(), "N-BARE")]);
            let (source, user) = (case.source.id().to_string(), case.target.id.clone());
            stub::Stub::serve(move |path, _| match path {
                stub::LIST => stub::ok(listing.clone()),
                stub::CREATE_ROOM => {
                    // The web session joins the source now, after the carry.
                    rt().block_on(set_voice_participant_session(
                        &source, &user, "F15WEB", None,
                    ))
                    .expect("the intruding join's record");
                    stub::ok(Vec::new())
                }
                stub::REMOVE => stub::ok(Vec::new()),
                _ => stub::internal(),
            })
        };
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        let seen = sfu.finish();
        let marker = get_user_moved_to_voice(case.destination.id(), &case.target.id)
            .await
            .unwrap();
        let admission = peek_move_admission(&case.target.id, case.destination.id())
            .await
            .unwrap();
        case.cleanup().await;

        assert_eq!(result.expect("an outcome"), VoiceMoveOutcome::NotConnected);
        assert!(
            on_session.is_empty() && on_user.is_empty(),
            "the kicked session must hear nothing: {on_session:?} {on_user:?}"
        );
        assert!(requested(&seen, stub::REMOVE).is_empty(), "nothing evicted: {seen:?}");
        assert_eq!((marker, admission), (None, None), "no label, no admission");
    }

    /// Merge slice P2A-10 / F8: a SWEEP move with no recorded owner is
    /// refused right after the expected-source check, before admission, the
    /// SFU or any write (control SWEEP-NONE). A moderator's is a disconnect.
    #[test]
    fn a_sweep_move_with_no_owner_is_refused_before_any_write() {
        rt().block_on(a_sweep_move_with_no_owner_is_refused_before_any_write_case())
    }

    async fn a_sweep_move_with_no_owner_is_refused_before_any_write_case() {
        let case = move_case("W").await;
        case.connect(None, None).await;
        let sfu = move_stub(&[(case.target.id.as_str(), "N-BARE")]);
        let voice_client = case.voice_client(&sfu);

        let mut results = Vec::new();
        for session in [None, Some("")] {
            results.push(case.move_now(&voice_client, session, MovePolicy::Sweep).await);
        }
        let seen = sfu.finish();
        let node = get_channel_node(case.destination.id()).await.unwrap();
        case.cleanup().await;

        for result in results {
            assert!(
                matches!(
                    result.as_ref().map_err(|error| &error.error_type),
                    Err(revolt_result::ErrorType::InvalidOperation)
                ),
                "{result:?}"
            );
        }
        assert!(seen.is_empty(), "no SFU call at all: {seen:?}");
        assert_eq!(node, None);
    }

    /// Merge slice P2A-4, end to end: a moderator's move of a target WITHOUT
    /// Connect writes the admission key naming exactly the identity it
    /// minted, and the voice-ingress re-check admits that identity (and only
    /// it) into the destination.
    #[test]
    fn a_moderator_move_without_connect_admits_the_minted_identity() {
        rt().block_on(a_moderator_move_without_connect_admits_the_minted_identity_case())
    }

    async fn a_moderator_move_without_connect_admits_the_minted_identity_case() {
        let mut case = move_case("A").await;
        let owner = unique_session("DESKTOP", &case);
        let owner = owner.as_str();
        case.deny_connect_on_destination().await;
        case.connect(Some(owner), None).await;
        let sfu = move_stub(&[(case.target.id.as_str(), "N-BARE")]);
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, _) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        sfu.finish();
        let admission = peek_move_admission(&case.target.id, case.destination.id())
            .await
            .unwrap();
        let (dest, user) = (case.destination.id(), case.target.id.as_str());
        let minted = voice_connect_still_allowed(&case.db, dest, user, user).await;
        let other = voice_connect_still_allowed(&case.db, dest, user, &format!("{user}:D9")).await;
        case.cleanup().await;

        assert!(matches!(result, Ok(VoiceMoveOutcome::Moved { .. })), "{result:?}");
        assert_eq!(on_session.len(), 1);
        assert_eq!(admission.as_deref(), Some(case.target.id.as_str()));
        assert!(minted.expect("the re-check reads"), "the minted identity is admitted");
        assert!(!other.expect("the re-check reads"), "no other identity is");
    }

    /// The admission, key by key: the exact identity is admitted, again on a
    /// reconnect within the lifetime (a peek, never a drain: control
    /// ADMIT-DRAIN); another identity or device is not (control
    /// ADMIT-ANYID); a non-member and a member banned since are not either,
    /// which the `ViewChannel` check refuses (the calculus grants a user with
    /// no member document nothing), not the membership read behind it. A
    /// self-move never writes one; an expired key admits nothing. A key for
    /// ANOTHER channel, and a revoked `ViewChannel` under a valid key, are
    /// `a_move_admission_needs_view_and_its_own_channel`.
    #[test]
    fn the_move_admission_admits_only_the_moved_identity() {
        rt().block_on(the_move_admission_admits_only_the_moved_identity_case())
    }

    async fn the_move_admission_admits_only_the_moved_identity_case() {
        use crate::{Member, RemovalIntention};

        let mut case = move_case("M").await;
        case.deny_connect_on_destination().await;
        let (dest, user) = (case.destination.id().to_string(), case.target.id.clone());
        let device = format!("{user}:D1");
        let outsider = User::create(&case.db, "F15Outsider".to_string(), None, None)
            .await
            .expect("`User`");

        async fn allowed(db: &Database, channel: &str, user: &str, identity: &str) -> bool {
            voice_connect_still_allowed(db, channel, user, identity)
                .await
                .expect("the re-check reads")
        }
        let db = &case.db;

        assert!(
            !allowed(db, &dest, &user, &device).await,
            "control: no Connect and no admission"
        );
        write_move_admission(&user, &dest, &device, MOVE_ADMISSION_TTL_SECS)
            .await
            .unwrap();
        write_move_admission(&outsider.id, &dest, &outsider.id, MOVE_ADMISSION_TTL_SECS)
            .await
            .unwrap();

        assert!(allowed(db, &dest, &user, &device).await, "admitted");
        assert!(
            allowed(db, &dest, &user, &device).await,
            "admitted again: a reconnect within the lifetime"
        );
        assert!(!allowed(db, &dest, &user, &user).await, "another identity");
        assert!(
            !allowed(db, &dest, &user, &format!("{user}:D2")).await,
            "another device"
        );
        assert!(
            !allowed(db, &dest, &outsider.id, &outsider.id).await,
            "a non-member is never admitted by a key"
        );

        let member = case
            .db
            .fetch_member(&case.server.id, &user)
            .await
            .expect("the member");
        member
            .remove(&case.db, &case.server, RemovalIntention::Ban, true)
            .await
            .expect("the ban");
        assert!(
            !allowed(db, &dest, &user, &device).await,
            "a member banned since the move is not admitted"
        );
        Member::create(&case.db, &case.server, &case.target, None)
            .await
            .expect("rejoined");

        // A self-move into the same channel is refused at admission and
        // writes no key of its own.
        let _: () = get_connection()
            .await
            .unwrap()
            .del(move_admission_key(&user, &dest))
            .await
            .unwrap();
        case.connect(Some("F15SELF"), None).await;
        let refused = case
            .move_now(
                &VoiceClient::new(Default::default()),
                Some("F15SELF"),
                MovePolicy::SelfMove {
                    request_session: Some("F15SELF"),
                },
            )
            .await;
        assert!(
            matches!(
                refused.as_ref().map_err(|error| &error.error_type),
                Err(revolt_result::ErrorType::MissingPermission { .. })
            ),
            "a self-move needs Connect: {refused:?}"
        );
        assert_eq!(peek_move_admission(&user, &dest).await.unwrap(), None);
        assert!(!allowed(db, &dest, &user, &user).await, "no exemption");

        // An expired key admits nothing; the same key unexpired did, above.
        write_move_admission(&user, &dest, &device, 1).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(2_100)).await;
        assert!(
            !allowed(db, &dest, &user, &device).await,
            "an expired admission"
        );

        let _: () = get_connection()
            .await
            .unwrap()
            .del(move_admission_key(&outsider.id, &dest))
            .await
            .unwrap();
        case.cleanup().await;
    }

    /// Merge slice M2B-1, end to end: a TOKENLESS move (the owner is not the
    /// session the moving seat's device is bound to) into a destination
    /// whose `max_users` is reached is refused `TargetCannotJoin` before any
    /// write: the owner's client would have to `join_call`, which refuses a
    /// full channel to anyone without `ManageChannel`, so carried out the
    /// target would land in no call. For a moderator's move and the sweep's
    /// alike (both bypass the cap when a token is delivered). Controls, both
    /// moved: a seat left, and `ManageChannel` on the destination. Red
    /// before the fix; control NOCAP (the occupancy half of the refusal
    /// deleted) fails here.
    #[test]
    fn a_tokenless_move_into_a_full_channel_is_refused() {
        rt().block_on(a_tokenless_move_into_a_full_channel_is_refused_case())
    }

    async fn a_tokenless_move_into_a_full_channel_is_refused_case() {
        for (policy, max_users, manages, refused) in [
            (MovePolicy::Moderator, 1, false, true),
            (MovePolicy::Sweep, 1, false, true),
            (MovePolicy::Moderator, 2, false, false),
            (MovePolicy::Moderator, 1, true, false),
        ] {
            let mut case = move_case("C").await;
            let owner = unique_session("WEB", &case);
            let owner = owner.as_str();
            if manages {
                case.override_destination(ChannelPermission::ManageChannel as i64, 0)
                    .await;
            }
            let occupants = case.fill_destination(max_users, 1).await;
            let identity = format!("{}:D1", case.target.id);
            case.db
                .insert_e2ee_identity(&identity_row(&case.target.id, "D1", "F15DESKTOP"))
                .await
                .expect("identity row");
            case.connect(Some(owner), Some("D1")).await;
            let sfu = move_stub(&[(identity.as_str(), "N-D1")]);
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                owner,
                case.move_now(&voice_client, Some(owner), policy),
            )
            .await;
            let seen = sfu.finish();
            let node = get_channel_node(case.destination.id()).await.unwrap();
            let carried = get_voice_participant_session(case.destination.id(), &case.target.id)
                .await
                .unwrap();
            case.empty_destination(&occupants).await;
            case.cleanup().await;

            let why = format!("{policy:?}, max_users {max_users}, ManageChannel {manages}");
            if refused {
                assert_eq!(
                    result.expect("an outcome, not an error"),
                    VoiceMoveOutcome::TargetCannotJoin,
                    "{why}"
                );
                assert!(on_session.is_empty() && on_user.is_empty(), "{why}");
                assert_eq!(
                    seen,
                    sfu_requests(&[(stub::LIST, "")]),
                    "{why}: nothing but the listing"
                );
                assert_eq!((node, carried), (None, None), "{why}: nothing written");
            } else {
                assert!(
                    matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
                    "{why}: {result:?}"
                );
                assert!(on_user.is_empty(), "{why}: {on_user:?}");
                assert_eq!(on_session.len(), 1, "{why}: {on_session:?}");
                assert_eq!(carried.as_deref(), Some(owner), "{why}");
            }
        }
    }

    /// Merge slice SEC2-2 / B4, end to end: a SELF-move is refused
    /// `NotAuthenticated` inside the move unless its request session is the
    /// one recorded as owning the participant: a sibling session, the
    /// session the moving device is bound to (but not the recorded owner),
    /// no session (a bot), an empty one, and ANY session when no owner is
    /// recorded (never `Disconnected`, which would be a self-kick). All with
    /// no SFU call and nothing written. The owning session itself then
    /// moves. Red before the fix; controls SELF-OWNER (the check deleted),
    /// NOREC and BOUND2 fail here.
    #[test]
    fn a_self_move_is_refused_unless_it_comes_from_the_owning_session() {
        rt().block_on(a_self_move_is_refused_unless_it_comes_from_the_owning_session_case())
    }

    async fn a_self_move_is_refused_unless_it_comes_from_the_owning_session_case() {
        let case = move_case("O").await;
        let owner = unique_session("WEB", &case);
        let owner = owner.as_str();
        let bound = unique_session("DESKTOP", &case);
        let identity = format!("{}:D1", case.target.id);
        case.db
            .insert_e2ee_identity(&identity_row(&case.target.id, "D1", &bound))
            .await
            .expect("identity row");
        case.connect(Some(owner), Some("D1")).await;

        let refusing = move_stub(&[(identity.as_str(), "N-D1")]);
        let voice_client = case.voice_client(&refusing);
        let mut refusals = Vec::new();
        for (recorded, request, why) in [
            (Some(owner), Some("F15SIBLING"), "a sibling session"),
            (
                Some(owner),
                Some(bound.as_str()),
                "the device's bound session, not the recorded owner",
            ),
            (Some(owner), None, "no session (a bot)"),
            (Some(owner), Some(""), "an empty session id"),
            (None, Some(owner), "no owner recorded"),
            (None, None, "no owner recorded and no session"),
        ] {
            let policy = MovePolicy::SelfMove {
                request_session: request,
            };
            refusals.push((why, case.move_now(&voice_client, recorded, policy).await));
        }
        let refused_seen = refusing.finish();
        let node = get_channel_node(case.destination.id()).await.unwrap();
        let carried = get_voice_participant_session(case.destination.id(), &case.target.id)
            .await
            .unwrap();

        // The owning session itself: moved, and told on its own topic.
        let sfu = move_stub(&[(identity.as_str(), "N-D1")]);
        let voice_client = case.voice_client(&sfu);
        let (moved, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(
                &voice_client,
                Some(owner),
                MovePolicy::SelfMove {
                    request_session: Some(owner),
                },
            ),
        )
        .await;
        sfu.finish();
        case.cleanup().await;

        for (why, result) in refusals {
            assert!(
                matches!(
                    result.as_ref().map_err(|error| &error.error_type),
                    Err(revolt_result::ErrorType::NotAuthenticated)
                ),
                "{why}: must be refused NotAuthenticated, got {result:?}"
            );
        }
        assert!(
            refused_seen.is_empty(),
            "a refused self-move calls no SFU: {refused_seen:?}"
        );
        assert_eq!(
            (node, carried),
            (None, None),
            "a refused self-move writes nothing"
        );
        assert!(
            matches!(moved, Ok(VoiceMoveOutcome::Moved { .. })),
            "the owning session moves: {moved:?}"
        );
        assert!(on_user.is_empty(), "{on_user:?}");
        assert_eq!(on_session.len(), 1, "{on_session:?}");
    }

    /// Merge slice SEC2-3, restated by RRB-1, end to end: under media E2EE
    /// the owner (a desktop session recorded as seated as its device D1,
    /// which is bound to it) is told about a move of the BARE seat the SFU
    /// lists (a sibling's; its own device seat is not listed) with NO token:
    /// a bare token would seat an E2EE client in the destination as a bare
    /// identity. Its client joins through `join_call` as its device. Red
    /// before SEC2-3 (a bare token went out); control MINT-BARE fails here.
    #[test]
    fn an_e2ee_owner_gets_no_bare_token_for_a_siblings_seat() {
        rt().block_on(an_e2ee_owner_gets_no_bare_token_for_a_siblings_seat_case())
    }

    async fn an_e2ee_owner_gets_no_bare_token_for_a_siblings_seat_case() {
        let case = move_case("E").await;
        let owner = unique_session("DESKTOP", &case);
        let owner = owner.as_str();
        case.db
            .insert_e2ee_identity(&identity_row(&case.target.id, "D1", owner))
            .await
            .expect("identity row");
        case.connect(Some(owner), Some("D1")).await;
        let sfu = move_stub(&[(case.target.id.as_str(), "N-BARE")]);
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        sfu.finish();
        case.cleanup().await;

        assert!(
            matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
            "{result:?}"
        );
        assert!(on_user.is_empty(), "{on_user:?}");
        assert_eq!(on_session.len(), 1, "{on_session:?}");
        let EventV1::UserMoveVoiceChannel {
            device_id,
            conn_nonce,
            token,
            ..
        } = on_session[0].clone()
        else {
            unreachable!()
        };
        assert_eq!(token, None, "no bare token for a session bound to a device");
        assert_eq!((device_id, conn_nonce), (None, None), "and no addressing");
    }

    /// Merge slice M2B-7, end to end: a web owner (seated bare, bound to no
    /// device) whose own BARE seat is listed next to a sibling's device seat
    /// (bound to the desktop session, and ranked first by the ordinary rules
    /// because it carries a nonce) moves ITS OWN seat, with a bare token. It
    /// used to be the sibling's device seat, told without a token: a
    /// needless `join_call`, or `TargetCannotJoin` without Connect. Red
    /// before the fix (M2B-7). Since merge slice SEC4-1 the bare token needs
    /// BOTH the recorded seat kind (bare) and the chosen connection (the
    /// bare seat), so choosing the owner's own seat is what gets it the
    /// token here (control SEAT-PREF-BARE, the owner's bare seat no longer
    /// preferred, and a Bare record told with no token both fail here); the
    /// choice is also pinned by value in
    /// `the_owner_seat_is_the_seat_recorded_at_its_join`. A Bare record with
    /// no bare seat listed is `a_bare_record_gets_no_token_for_a_device_seat`.
    #[test]
    fn a_web_owner_moves_its_own_bare_seat_before_a_siblings_device() {
        rt().block_on(a_web_owner_moves_its_own_bare_seat_before_a_siblings_device_case())
    }

    async fn a_web_owner_moves_its_own_bare_seat_before_a_siblings_device_case() {
        let case = move_case("B").await;
        let owner = unique_session("WEB", &case);
        let owner = owner.as_str();
        let device_seat = format!("{}:D1", case.target.id);
        case.db
            .insert_e2ee_identity(&identity_row(&case.target.id, "D1", "F15DESKTOP"))
            .await
            .expect("identity row");
        case.connect(Some(owner), None).await;
        let sfu = move_stub(&[
            (device_seat.as_str(), "N-D1"),
            (case.target.id.as_str(), ""),
        ]);
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        let seen = sfu.finish();
        case.cleanup().await;

        assert!(
            matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
            "{result:?}"
        );
        assert!(on_user.is_empty(), "{on_user:?}");
        assert_eq!(on_session.len(), 1, "{on_session:?}");
        let EventV1::UserMoveVoiceChannel {
            device_id,
            conn_nonce,
            token,
            ..
        } = on_session[0].clone()
        else {
            unreachable!()
        };
        let token = token.expect("the owner's own bare seat gets a bare token");
        let claims =
            livekit_api::access_token::Claims::from_unverified(&token).expect("decode token");
        assert_eq!(claims.sub, case.target.id, "minted for the bare seat");
        assert_eq!(
            (device_id, conn_nonce),
            (None, None),
            "a bare seat is never named"
        );
        let removed = requested(&seen, stub::REMOVE);
        assert!(
            removed.contains(&case.target.id) && removed.contains(&device_seat),
            "both connections leave the source: {seen:?}"
        );
    }

    /// Merge slice RRB-1, end to end: an owner recorded as seated as device
    /// D1 gets a token for D1 and for nothing else. Its session is bound to
    /// D0 as well, and D0's seat is listed too and ranked first by the
    /// ordinary rules (both carry a nonce, D0 is the smaller identity), but
    /// the move chooses and mints for the recorded D1, names that
    /// connection, and the destination records the owner seated as D1. With
    /// D1's seat not listed (D0's and a bare seat are), the owner is told
    /// with no token and no addressing: never a token for D0, never a bare
    /// one. Controls OTHER-DEVICE, SEAT-PREF, MINT-BARE and CARRY-NOSEAT
    /// fail here.
    #[test]
    fn a_device_seated_owner_gets_a_token_for_its_recorded_device_only() {
        rt().block_on(a_device_seated_owner_gets_a_token_for_its_recorded_device_only_case())
    }

    async fn a_device_seated_owner_gets_a_token_for_its_recorded_device_only_case() {
        for d1_listed in [true, false] {
            let case = move_case("G").await;
            let owner = unique_session("DESKTOP", &case);
            let owner = owner.as_str();
            let (d0, d1) = (
                format!("{}:D0", case.target.id),
                format!("{}:D1", case.target.id),
            );
            for device in ["D0", "D1"] {
                case.db
                    .insert_e2ee_identity(&identity_row(&case.target.id, device, owner))
                    .await
                    .expect("identity row");
            }
            case.connect(Some(owner), Some("D1")).await;
            let listing: Vec<(&str, &str)> = if d1_listed {
                vec![(d0.as_str(), "N-D0"), (d1.as_str(), "N-D1")]
            } else {
                vec![(d0.as_str(), "N-D0"), (case.target.id.as_str(), "")]
            };
            let sfu = move_stub(&listing);
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                owner,
                case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
            )
            .await;
            let seen = sfu.finish();
            let carried =
                get_voice_participant_session_seat(case.destination.id(), &case.target.id)
                    .await
                    .unwrap();
            case.cleanup().await;

            let why = format!("D1 listed: {d1_listed}");
            assert!(
                matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
                "{why}: {result:?}"
            );
            assert!(on_user.is_empty(), "{why}: {on_user:?}");
            assert_eq!(on_session.len(), 1, "{why}: {on_session:?}");
            let EventV1::UserMoveVoiceChannel {
                device_id,
                conn_nonce,
                token,
                ..
            } = on_session[0].clone()
            else {
                unreachable!()
            };
            if d1_listed {
                let token = token.expect("the recorded device's seat gets its token");
                let claims = livekit_api::access_token::Claims::from_unverified(&token)
                    .expect("decode token");
                assert_eq!(claims.sub, d1, "{why}: minted for the recorded device only");
                assert_eq!(
                    (device_id.as_deref(), conn_nonce.as_deref()),
                    (Some("D1"), Some("N-D1")),
                    "{why}: the recorded device's connection is named"
                );
            } else {
                assert_eq!(token, None, "{why}: no token for D0, and no bare one");
                assert_eq!(
                    (device_id, conn_nonce),
                    (None, None),
                    "{why}: no addressing"
                );
            }
            assert_eq!(
                carried,
                Some((owner.to_string(), SeatKind::Device("D1".to_string()))),
                "{why}: the destination records the owner seated as D1"
            );
            assert!(
                requested(&seen, stub::REMOVE).contains(&d0),
                "{why}: every connection leaves the source: {seen:?}"
            );
        }
    }

    /// Merge slice RRB-1, the finding itself, end to end: a NATIVE owner
    /// whose session is bound to device D1 (an identity row) but which
    /// joined BARE (no media E2EE on that client, a key-provider failure)
    /// is recorded as seated bare, and a move gets it a BARE token, like
    /// any bare seat. So a moderator's move into a channel the target
    /// cannot Connect to (the timeout channel, D0-1) goes ahead and admits
    /// the bare identity, where R-M2b's "bound to any device" rule told it
    /// with no token and answered `TargetCannotJoin`. Red against
    /// `870425f2`'s behavior (control RRB1-OLD puts that rule back).
    #[test]
    fn a_bare_seated_owner_bound_to_a_device_gets_a_bare_token() {
        rt().block_on(a_bare_seated_owner_bound_to_a_device_gets_a_bare_token_case())
    }

    async fn a_bare_seated_owner_bound_to_a_device_gets_a_bare_token_case() {
        let mut case = move_case("H").await;
        let owner = unique_session("ELECTRON", &case);
        let owner = owner.as_str();
        case.deny_connect_on_destination().await;
        case.db
            .insert_e2ee_identity(&identity_row(&case.target.id, "D1", owner))
            .await
            .expect("identity row");
        case.connect(Some(owner), None).await;
        let sfu = move_stub(&[(case.target.id.as_str(), "N-BARE")]);
        let voice_client = case.voice_client(&sfu);

        let (result, on_session, on_user) = moves_published_by(
            &case.target.id,
            owner,
            case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
        )
        .await;
        let seen = sfu.finish();
        let admission = peek_move_admission(&case.target.id, case.destination.id())
            .await
            .unwrap();
        let carried = get_voice_participant_session_seat(case.destination.id(), &case.target.id)
            .await
            .unwrap();
        case.cleanup().await;

        assert!(
            matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
            "a bare seat is moved like any bare seat, not refused: {result:?}"
        );
        assert!(on_user.is_empty(), "{on_user:?}");
        assert_eq!(on_session.len(), 1, "{on_session:?}");
        let EventV1::UserMoveVoiceChannel {
            device_id,
            conn_nonce,
            token,
            ..
        } = on_session[0].clone()
        else {
            unreachable!()
        };
        let token = token.expect("the bare-seated owner gets a bare token");
        let claims =
            livekit_api::access_token::Claims::from_unverified(&token).expect("decode token");
        assert_eq!(claims.sub, case.target.id, "minted for the bare identity");
        assert_eq!(
            (device_id, conn_nonce),
            (None, None),
            "a bare seat is never named"
        );
        assert_eq!(
            admission.as_deref(),
            Some(case.target.id.as_str()),
            "the bare identity is admitted past Connect (D0-1)"
        );
        assert_eq!(
            carried,
            Some((owner.to_string(), SeatKind::Bare)),
            "the destination records the owner seated bare"
        );
        assert_eq!(requested(&seen, stub::CREATE_ROOM).len(), 1, "{seen:?}");
    }

    /// Merge slice SEC4-1, end to end: an owner recorded as seated BARE (its
    /// last `join_call` token was bare) whose bare seat the SFU does not
    /// list, while a device seat of the target is (here the owner's own
    /// device D1, bound to it: the owner has connected with a device token
    /// since), is told with NO token: never a bare token for a connection
    /// the SFU lists as a device, and so never an admission key for one.
    /// With Connect on the destination the owner is told tokenless and joins
    /// through `join_call`; without it the tokenless move is refused before
    /// any write (P2A-3), where a bare token used to carry an admission key
    /// past Connect. Control BARE-ANYSEAT (the bare token whichever seat is
    /// chosen) fails here.
    #[test]
    fn a_bare_record_gets_no_token_for_a_device_seat() {
        rt().block_on(a_bare_record_gets_no_token_for_a_device_seat_case())
    }

    async fn a_bare_record_gets_no_token_for_a_device_seat_case() {
        for connect in [true, false] {
            let mut case = move_case("J").await;
            let owner = unique_session("DESKTOP", &case);
            let owner = owner.as_str();
            let d1 = format!("{}:D1", case.target.id);
            if !connect {
                case.deny_connect_on_destination().await;
            }
            case.db
                .insert_e2ee_identity(&identity_row(&case.target.id, "D1", owner))
                .await
                .expect("identity row");
            case.connect(Some(owner), None).await;
            let sfu = move_stub(&[(d1.as_str(), "N-D1")]);
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                owner,
                case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
            )
            .await;
            let seen = sfu.finish();
            let admission = peek_move_admission(&case.target.id, case.destination.id())
                .await
                .unwrap();
            case.cleanup().await;

            let why = format!("Connect on the destination: {connect}");
            assert!(on_user.is_empty(), "{why}: {on_user:?}");
            assert_eq!(admission, None, "{why}: no admission key");
            if connect {
                assert!(
                    matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
                    "{why}: {result:?}"
                );
                assert_eq!(on_session.len(), 1, "{why}: {on_session:?}");
                let EventV1::UserMoveVoiceChannel {
                    device_id,
                    conn_nonce,
                    token,
                    ..
                } = on_session[0].clone()
                else {
                    unreachable!()
                };
                assert_eq!(token, None, "{why}: no bare token for a device seat");
                assert_eq!(
                    (device_id, conn_nonce),
                    (None, None),
                    "{why}: no addressing"
                );
            } else {
                assert_eq!(
                    result.expect("an outcome"),
                    VoiceMoveOutcome::TargetCannotJoin,
                    "{why}"
                );
                assert!(on_session.is_empty(), "{why}: {on_session:?}");
                assert!(
                    requested(&seen, stub::CREATE_ROOM).is_empty()
                        && requested(&seen, stub::REMOVE).is_empty(),
                    "{why}: refused before any write: {seen:?}"
                );
            }
        }
    }

    /// Merge slice SEC4-2, end to end: the SAME session joins the source
    /// again as another kind of seat between the carry-over and the
    /// announcement (simulated at the room creation, which follows the
    /// carry): from bare to its device D1, or from D1 to bare. The token the
    /// move minted is of the old kind, so the owner re-check, which compares
    /// the whole record (the session and the seat kind the carry compared),
    /// refuses: `NotConnected`, nothing announced, labeled, admitted or
    /// evicted. Control RECHECK-SESSION (the re-check back to the session
    /// alone) announces the stale token and fails here.
    #[test]
    fn a_same_session_seat_change_after_the_carry_refuses_the_move() {
        rt().block_on(a_same_session_seat_change_after_the_carry_refuses_the_move_case())
    }

    async fn a_same_session_seat_change_after_the_carry_refuses_the_move_case() {
        for (before, after) in [(None, Some("D1")), (Some("D1"), None)] {
            let mut case = move_case("R").await;
            let owner = unique_session("DESKTOP", &case);
            case.deny_connect_on_destination().await;
            case.db
                .insert_e2ee_identity(&identity_row(&case.target.id, "D1", &owner))
                .await
                .expect("identity row");
            case.connect(Some(&owner), before).await;
            let listed = move_token_identity(&case.target.id, before);
            let sfu = {
                let listing = stub::list_participants_response(&[(listed.as_str(), "N-SEAT")]);
                let (source, user, session) = (
                    case.source.id().to_string(),
                    case.target.id.clone(),
                    owner.clone(),
                );
                stub::Stub::serve(move |path, _| match path {
                    stub::LIST => stub::ok(listing.clone()),
                    stub::CREATE_ROOM => {
                        // The owning session joins the source again, now
                        // seated as `after`, after the carry.
                        rt().block_on(set_voice_participant_session(
                            &source, &user, &session, after,
                        ))
                        .expect("the same session's rejoin");
                        stub::ok(Vec::new())
                    }
                    stub::REMOVE => stub::ok(Vec::new()),
                    _ => stub::internal(),
                })
            };
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                &owner,
                case.move_now(&voice_client, Some(&owner), MovePolicy::Moderator),
            )
            .await;
            let seen = sfu.finish();
            let rejoined = get_voice_participant_session_seat(case.source.id(), &case.target.id)
                .await
                .unwrap();
            let marker = get_user_moved_to_voice(case.destination.id(), &case.target.id)
                .await
                .unwrap();
            let admission = peek_move_admission(&case.target.id, case.destination.id())
                .await
                .unwrap();
            case.cleanup().await;

            let why = format!("seated {before:?}, then {after:?}");
            let after_seat = match after {
                Some(device) => SeatKind::Device(device.to_string()),
                None => SeatKind::Bare,
            };
            assert_eq!(
                rejoined,
                Some((owner.clone(), after_seat)),
                "{why}: the rejoin ran between the carry and the announcement"
            );
            assert_eq!(
                result.expect("an outcome"),
                VoiceMoveOutcome::NotConnected,
                "{why}"
            );
            assert!(
                on_session.is_empty() && on_user.is_empty(),
                "{why}: a token of the old seat kind must not be announced: {on_session:?} \
                 {on_user:?}"
            );
            assert!(
                requested(&seen, stub::REMOVE).is_empty(),
                "{why}: nothing evicted: {seen:?}"
            );
            assert_eq!(
                (marker, admission),
                (None, None),
                "{why}: no label, no admission"
            );
        }
    }

    /// Media-e2ee S6M-3, end to end: the owner is recorded as seated as
    /// device D1, and D1's identity row is bound to it when the move plans
    /// its delivery, so the move mints a D1 token. Between the plan and the
    /// announcement (simulated at the room creation, which follows the
    /// carry and precedes the release and the mint) D1 is revoked, or
    /// re-bound to another session. The binding re-read right before the
    /// owner re-check refuses: `NotConnected`, the D1 token never published,
    /// nothing labeled, admitted or evicted, while the source record still
    /// names the owner seated as D1 (so the owner re-check alone would have
    /// passed).
    /// Left unchanged, the same move is announced with the D1 token, so the
    /// interposition breaks nothing by itself. Control REREAD (the re-read
    /// deleted) announces the stale token and fails here.
    #[test]
    fn a_device_revoked_or_rebound_after_the_plan_refuses_the_move() {
        rt().block_on(a_device_revoked_or_rebound_after_the_plan_refuses_the_move_case())
    }

    async fn a_device_revoked_or_rebound_after_the_plan_refuses_the_move_case() {
        for change in ["unchanged", "revoked", "rebound"] {
            let mut case = move_case("V").await;
            let owner = unique_session("DESKTOP", &case);
            case.deny_connect_on_destination().await;
            case.db
                .insert_e2ee_identity(&identity_row(&case.target.id, "D1", &owner))
                .await
                .expect("identity row");
            case.connect(Some(&owner), Some("D1")).await;
            let d1 = move_token_identity(&case.target.id, Some("D1"));
            let sfu = {
                let listing = stub::list_participants_response(&[(d1.as_str(), "N-D1")]);
                let (db, user) = (case.db.clone(), case.target.id.clone());
                stub::Stub::serve(move |path, _| match path {
                    stub::LIST => stub::ok(listing.clone()),
                    stub::CREATE_ROOM => {
                        // D1's binding changes now, after the plan read it.
                        match change {
                            "revoked" => {
                                rt().block_on(crate::E2EEIdentity::revoke_device(&db, &user, "D1"))
                                    .expect("the revocation");
                            }
                            "rebound" => {
                                rt().block_on(db.update_e2ee_identity_session(
                                    &user,
                                    "D1",
                                    "F15ELSEWHERE",
                                    Timestamp::now_utc(),
                                ))
                                .expect("the re-binding");
                            }
                            _ => {}
                        }
                        stub::ok(Vec::new())
                    }
                    stub::REMOVE => stub::ok(Vec::new()),
                    _ => stub::internal(),
                })
            };
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                &owner,
                case.move_now(&voice_client, Some(&owner), MovePolicy::Moderator),
            )
            .await;
            let seen = sfu.finish();
            let source_record =
                get_voice_participant_session_seat(case.source.id(), &case.target.id)
                    .await
                    .unwrap();
            let marker = get_user_moved_to_voice(case.destination.id(), &case.target.id)
                .await
                .unwrap();
            let admission = peek_move_admission(&case.target.id, case.destination.id())
                .await
                .unwrap();
            case.cleanup().await;

            let why = format!("D1 {change} between the plan and the announcement");
            assert_eq!(
                source_record,
                Some((owner.clone(), SeatKind::Device("D1".to_string()))),
                "{why}: the source record is untouched, so the owner re-check alone would pass"
            );
            assert!(
                on_user.is_empty(),
                "{why}: nothing on the user topic: {on_user:?}"
            );
            if change == "unchanged" {
                assert!(
                    matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
                    "{why}: {result:?}"
                );
                assert_eq!(on_session.len(), 1, "{why}: {on_session:?}");
                let EventV1::UserMoveVoiceChannel { token, .. } = on_session[0].clone() else {
                    unreachable!()
                };
                let token = token.unwrap_or_else(|| panic!("{why}: the D1 token"));
                let claims = livekit_api::access_token::Claims::from_unverified(&token)
                    .expect("decode token");
                assert_eq!(claims.sub, d1, "{why}: minted for D1");
                assert_eq!(
                    admission.as_deref(),
                    Some(d1.as_str()),
                    "{why}: D1 admitted"
                );
                assert!(marker.is_some(), "{why}: the Join label is written");
                assert!(
                    requested(&seen, stub::REMOVE).contains(&d1),
                    "{why}: the moved seat leaves the source: {seen:?}"
                );
            } else {
                assert_eq!(
                    result.expect("an outcome"),
                    VoiceMoveOutcome::NotConnected,
                    "{why}"
                );
                assert!(
                    on_session.is_empty(),
                    "{why}: the D1 token must not be announced: {on_session:?}"
                );
                assert!(
                    requested(&seen, stub::REMOVE).is_empty(),
                    "{why}: nothing evicted: {seen:?}"
                );
                assert_eq!(
                    (marker, admission),
                    (None, None),
                    "{why}: no label, no admission"
                );
            }
        }
    }

    /// Merge slice RRB-1, end to end: a record with no seat kind (written
    /// before the seat kind was recorded: the session id alone) is told with
    /// no token, whatever seat is listed: its bare seat, or a device seat
    /// bound to it. The destination keeps the record as it was (still
    /// unknown). Control UNKNOWN-BARE fails here.
    #[test]
    fn a_legacy_record_with_no_seat_kind_gets_no_token() {
        rt().block_on(a_legacy_record_with_no_seat_kind_gets_no_token_case())
    }

    async fn a_legacy_record_with_no_seat_kind_gets_no_token_case() {
        for device in [None, Some("D1")] {
            let case = move_case("L").await;
            let owner = unique_session("LEGACY", &case);
            let owner = owner.as_str();
            let identity = move_token_identity(&case.target.id, device);
            if let Some(device) = device {
                case.db
                    .insert_e2ee_identity(&identity_row(&case.target.id, device, owner))
                    .await
                    .expect("identity row");
            }
            case.connect(None, None).await;
            let _: () = get_connection()
                .await
                .unwrap()
                .hset(voice_session_key(case.source.id()), &case.target.id, owner)
                .await
                .unwrap();
            let sfu = move_stub(&[(identity.as_str(), "N-LEGACY")]);
            let voice_client = case.voice_client(&sfu);

            let (result, on_session, on_user) = moves_published_by(
                &case.target.id,
                owner,
                case.move_now(&voice_client, Some(owner), MovePolicy::Moderator),
            )
            .await;
            sfu.finish();
            let carried =
                get_voice_participant_session_seat(case.destination.id(), &case.target.id)
                    .await
                    .unwrap();
            case.cleanup().await;

            assert!(
                matches!(result, Ok(VoiceMoveOutcome::Moved { .. })),
                "{device:?}: {result:?}"
            );
            assert!(on_user.is_empty(), "{device:?}: {on_user:?}");
            assert_eq!(on_session.len(), 1, "{device:?}: {on_session:?}");
            let EventV1::UserMoveVoiceChannel {
                device_id,
                conn_nonce,
                token,
                ..
            } = on_session[0].clone()
            else {
                unreachable!()
            };
            assert_eq!(
                token, None,
                "{device:?}: an unknown seat kind gets no token"
            );
            assert_eq!((device_id, conn_nonce), (None, None), "{device:?}");
            assert_eq!(
                carried,
                Some((owner.to_string(), SeatKind::Unknown)),
                "{device:?}: carried as it was"
            );
        }
    }

    /// Merge slice SEC2-4: the move admission holds only for the channel it
    /// was written for, and only while the target can still VIEW it. A key
    /// naming the same identity for ANOTHER channel admits nothing here
    /// (control KEY-ANYCHAN), and a member whose `ViewChannel` is revoked
    /// while the key is still valid is refused (control NOVIEW), where the
    /// same key admitted them a moment before.
    #[test]
    fn a_move_admission_needs_view_and_its_own_channel() {
        rt().block_on(a_move_admission_needs_view_and_its_own_channel_case())
    }

    async fn a_move_admission_needs_view_and_its_own_channel_case() {
        let mut case = move_case("V").await;
        case.override_destination(0, ChannelPermission::Connect as i64)
            .await;
        let (dest, user) = (case.destination.id().to_string(), case.target.id.clone());
        let elsewhere = case.source.id().to_string();
        let identity = format!("{user}:D1");

        async fn allowed(db: &Database, channel: &str, user: &str, identity: &str) -> bool {
            voice_connect_still_allowed(db, channel, user, identity)
                .await
                .expect("the re-check reads")
        }

        write_move_admission(&user, &elsewhere, &identity, MOVE_ADMISSION_TTL_SECS)
            .await
            .unwrap();
        let another_channel = allowed(&case.db, &dest, &user, &identity).await;
        write_move_admission(&user, &dest, &identity, MOVE_ADMISSION_TTL_SECS)
            .await
            .unwrap();
        let own_channel = allowed(&case.db, &dest, &user, &identity).await;

        case.override_destination(
            0,
            ChannelPermission::Connect as i64 | ChannelPermission::ViewChannel as i64,
        )
        .await;
        let view_revoked = allowed(&case.db, &dest, &user, &identity).await;

        let _: () = get_connection()
            .await
            .unwrap()
            .del(move_admission_key(&user, &elsewhere))
            .await
            .unwrap();
        case.cleanup().await;

        assert!(
            !another_channel,
            "a key for another channel admits nothing here"
        );
        assert!(
            own_channel,
            "control: the channel's own key admits the identity"
        );
        assert!(
            !view_revoked,
            "a member who can no longer view the channel is refused under a valid key"
        );
    }

    /// Merge slice SEC2-5: a privileged (staff) account that is NOT a member
    /// of the destination's server is `NotFound` for a move under every
    /// policy, from the move's admission and its pre-flight alike: the
    /// calculus waves a privileged account through with GrantAllSafe before
    /// it looks at membership, so the explicit membership read is what
    /// refuses it. Made a member, the same account is admitted (control).
    /// Control NOMEMBER (the membership read deleted) fails here. On the
    /// database `TEST_DB` names.
    #[test]
    fn a_privileged_non_member_is_not_found_for_a_move() {
        rt().block_on(async {
            database_test!(|db| async move { a_privileged_non_member_case(db).await });
        })
    }

    async fn a_privileged_non_member_case(db: Database) {
        use crate::Member;
        use revolt_models::v0::{
            DataCreateServer, DataCreateServerChannel, LegacyServerChannelType,
        };

        let owner = User::create(&db, "StaffCaseOwner".to_string(), None, None)
            .await
            .expect("`User`");
        let mut server = Server::create(
            &db,
            DataCreateServer {
                name: "StaffCaseServer".to_string(),
                description: None,
                nsfw: None,
            },
            &owner,
            false,
        )
        .await
        .expect("`Server`")
        .0;
        let destination = Channel::create_server_channel(
            &db,
            &mut server,
            DataCreateServerChannel {
                channel_type: LegacyServerChannelType::Voice,
                name: "Destination".to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("`Channel`");
        let mut staff = User::create(&db, "StaffCaseStaff".to_string(), None, None)
            .await
            .expect("`User`");
        staff.privileged = true;

        let policies = [
            MovePolicy::Moderator,
            MovePolicy::SelfMove {
                request_session: None,
            },
            MovePolicy::Sweep,
        ];
        for policy in policies {
            let admitted = admit_voice_move(&db, &staff, &destination, policy).await;
            assert!(
                matches!(
                    admitted.as_ref().map_err(|error| &error.error_type),
                    Err(revolt_result::ErrorType::NotFound)
                ),
                "{policy:?}: a privileged non-member must be NotFound, got {admitted:?}"
            );
            let preflight = assert_voice_move_admissible(&db, &staff, &destination, policy).await;
            assert!(
                matches!(
                    preflight.as_ref().map_err(|error| &error.error_type),
                    Err(revolt_result::ErrorType::NotFound)
                ),
                "{policy:?}: the pre-flight agrees, got {preflight:?}"
            );
        }

        Member::create(&db, &server, &staff, None)
            .await
            .expect("`Member`");
        for policy in policies {
            admit_voice_move(&db, &staff, &destination, policy)
                .await
                .unwrap_or_else(|error| {
                    panic!("{policy:?}: control: a privileged MEMBER is admitted, got {error:?}")
                });
        }
    }

    /// Voice-move's `a_revoked_device_gets_no_move_token`, on the database
    /// `TEST_DB` names (Reference or MongoDB, merge slice M2B-4): revocation
    /// deletes the identity row, so the move's lookup comes back empty for
    /// it and the delivery for an owner recorded as seated as that device
    /// carries no token (merge slice RRB-1: never a bare one either).
    #[test]
    fn a_revoked_device_gets_no_move_token() {
        rt().block_on(async {
            database_test!(|db| async move { a_revoked_device_gets_no_move_token_case(db).await });
        })
    }

    async fn a_revoked_device_gets_no_move_token_case(db: Database) {
        let user = User::create(&db, "F15Revoked".to_string(), None, None)
            .await
            .expect("`User`");
        let (session, device) = ("F15SESSION", "cd".repeat(16));
        db.insert_e2ee_identity(&identity_row(&user.id, &device, session))
            .await
            .expect("identity");

        let seat = SeatKind::Device(device.clone());

        let row = fetch_device_identity(&db, &user.id, &device)
            .await
            .expect("lookup");
        assert_eq!(
            move_event_delivery(
                Some(session),
                &seat,
                Some(&device),
                false, // the device's own seat is chosen, not the bare one
                row.as_ref().map(|row| row.last_session_id.as_str()),
            ),
            MoveDelivery::Session {
                session_id: session.to_string(),
                device_id: Some(device.clone())
            }
        );

        crate::E2EEIdentity::revoke_device(&db, &user.id, &device)
            .await
            .expect("revoke");

        let row = fetch_device_identity(&db, &user.id, &device)
            .await
            .expect("lookup");
        assert!(row.is_none(), "a revoked device has no identity row");
        assert_eq!(
            move_event_delivery(
                Some(session),
                &seat,
                Some(&device),
                false, // the device's own seat is chosen, not the bare one
                row.as_ref().map(|row| row.last_session_id.as_str()),
            ),
            MoveDelivery::SessionNoToken {
                session_id: session.to_string()
            }
        );
    }

    /// `VOICE_STATE_KEY_PREFIXES` is the list the writers, the reader and
    /// BOTH teardowns agree on: a key written or read under the unique key
    /// elsewhere but missing from it would survive every leave. The two
    /// teardowns spell their keys out (the script's `KEYS[8..]` and the
    /// fallback's DEL, each pinned by value elsewhere), so they are held to
    /// the list here, in the list's order (merge slice M2A-1: a tenth flag
    /// added to the list and the writers but not to a teardown used to pass
    /// every pin and leak). Textual, like the permission contracts.
    #[test]
    fn voice_state_key_list_matches_create_update_and_get() {
        let source = include_str!("mod.rs");
        let prefixes_in = |fn_name: &str| -> Vec<String> {
            let start = source
                .find(&format!("fn {fn_name}("))
                .unwrap_or_else(|| panic!("{fn_name} left voice/mod.rs"));
            // The fn itself, up to its closing brace in column 0. Not "up to
            // the next `pub async fn`": after the AFK merge that span runs on
            // past `create_voice_state` into the teardown's own key list.
            let end = start
                + source[start..]
                    .find("\n\u{7d}\n")
                    .expect("the end of the fn");
            let body = &source[start..end];
            body.match_indices(":{unique_key}\"")
                .map(|(at, _)| {
                    let open = body[..at].rfind('"').expect("a key literal") + 1;
                    body[open..at].to_string()
                })
                .collect()
        };
        let listed: Vec<String> = VOICE_STATE_KEY_PREFIXES
            .iter()
            .map(ToString::to_string)
            .collect();

        let mut created = prefixes_in("create_voice_state");
        created.sort();
        let mut listed_sorted = listed.clone();
        listed_sorted.sort();
        assert_eq!(
            created, listed_sorted,
            "create_voice_state must write exactly the listed keys"
        );

        assert_eq!(
            prefixes_in("get_voice_state"),
            listed,
            "get_voice_state must read exactly the listed keys"
        );

        let updated = prefixes_in("update_voice_state");
        assert!(!updated.is_empty(), "update_voice_state scan found nothing");
        for prefix in updated {
            assert!(
                listed.contains(&prefix),
                "update_voice_state writes `{prefix}`, missing from the list"
            );
        }

        for teardown in [
            "voice_state_teardown_input",
            "delete_voice_state_unconditionally",
        ] {
            assert_eq!(
                prefixes_in(teardown),
                listed,
                "{teardown} must tear down exactly the listed keys, in the list's order"
            );
        }
    }
}
