use std::{
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
pub use voice_client::{screen_leg_participant_permissions, VoiceClient};

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
/// participant's full identity here (a hash per channel) so
/// `update_participant`/`remove_participant` can resolve the identity the
/// SFU actually knows. User ids are ULIDs and never contain `:`, so the
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
/// correct for an account sitting in a room twice — the voice-move eviction —
/// must ask the SFU for its participant list instead, as the voice move does
/// through `VoiceClient::list_participants_if_present`; see
/// `select_move_connection` and `eviction_targets`. Reconciling the map against the live SFU participant
/// set (for the Redis-eviction / missed-webhook case, where a stale/absent
/// mapping makes a kick target a bare id the SFU no longer knows) is the
/// roster-reconciliation work in 6.4; until then `get_voice_participant_identity`
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
    let stored = stored_voice_participant_identity(channel_id, user_id).await?;

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
/// literal that could drift from it.
pub const MOVED_TO_MARKER_TTL_SECS: usize = 10;

/// The voice move's ONE marker: for [`MOVED_TO_MARKER_TTL_SECS`], the target's
/// next join to `new_channel_id` is announced as a `VoiceChannelMove` from
/// `old_channel` instead of a `VoiceChannelJoin`. A label only. There is no
/// counterpart for the source any more: its Leave is always published (Wave
/// 5b-2 M4-b), so a move whose destination join never comes cannot leave a
/// ghost on the other clients' rosters.
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
        .query_async::<_, ()>(&mut get_connection().await?.into_inner())
        .await
        .to_internal_error()?;

    Ok(voice_state)
}

/// Lua source of [`DELETE_VOICE_STATE`]: the WHOLE of one user's voice-state
/// teardown in one channel, as one atomic step.
///
/// Argument layout. [`voice_state_teardown_input`] builds it and nothing else
/// does, so the two change together or not at all (both are pinned by value
/// in the tests):
///
/// - `KEYS[1]`: the per-server pointer `{user}:{parent}`. Its value is the id
///   of the channel the user's per-server state belongs to.
/// - `KEYS[2]`: `vc_members:{channel}`, a set of user ids.
/// - `KEYS[3]`: `vc:{user}`, the user's set of `UserVoiceChannel` strings.
/// - `KEYS[4]`: `vc_leg:{channel}`, a hash keyed by user id.
/// - `KEYS[5]`: `voice_identity:{channel}`, a hash keyed by user id.
/// - `KEYS[6]`: `annotations_allow:{channel}:{user}`, deleted whole.
/// - `KEYS[7..]`: the nine per-server flags keyed by the pointer
///   (`joined_at:`, `is_publishing:`, `is_receiving:`, `screensharing:`,
///   `camera:`, `screen_video:`, `recording:`, `rc_capable:`, `watching:`).
/// - `ARGV[1]`: the id of the channel being left, compared with the pointer.
/// - `ARGV[2]`: the user id. It is the member removed from `KEYS[2]` and the
///   field removed from `KEYS[4]` and `KEYS[5]`.
/// - `ARGV[3]`: this channel as `vc:{user}` stores it, which is
///   `UserVoiceChannel`'s `Display`: the channel id, then `-` and the server
///   id when there is one.
///
/// `KEYS[2]` to `KEYS[6]` are PER-CHANNEL and always go. `KEYS[1]` and
/// `KEYS[7..]` are PER-SERVER and go UNLESS the pointer names a DIFFERENT
/// channel. A missing pointer reads as Lua `false` and falls through to the
/// delete: with no pointer there is nothing newer to protect, and the flags
/// are orphans. Returns 1 when the per-server state was deleted, 0 when it
/// was kept.
const DELETE_VOICE_STATE_LUA: &str = r"
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('SREM', KEYS[3], ARGV[3])
redis.call('HDEL', KEYS[4], ARGV[2])
redis.call('HDEL', KEYS[5], ARGV[2])
redis.call('DEL', KEYS[6])
local pointer = redis.call('GET', KEYS[1])
if pointer and pointer ~= ARGV[1] then
    return 0
end
redis.call('DEL', KEYS[1], unpack(KEYS, 7))
return 1
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
/// here makes it enough: the 15 keys carry no shared hash tag, so they span
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
            // Safe at every caller, because every one of them either has
            // already used the identity or never needed it: the ingress leave
            // paths and the reconcile sweep call
            // `delete_voice_participant_identity` immediately after this (now
            // redundant, still harmless — HDEL is idempotent);
            // `remove_user_from_voice_channel`, `voice_join`'s force-disconnect
            // and the ingress admission backstop all issue their `remove_user`
            // BEFORE reaching here, and that is the call that reads the
            // mapping; and `get_channel_voice_state`'s roster repair is clearing
            // a member whose voice state is already gone. Nothing in the
            // workspace reads `get_voice_participant_identity` for a user after
            // tearing their voice state down.
            //
            // The hash can hold only ONE field per user, so clearing it on one
            // connection's departure cannot discard a mapping that some other
            // live connection of theirs was relying on — there was never
            // anywhere for a second one to live. That is the same limitation
            // the eviction leg of `move_user_to_voice_channel` exists to work
            // around.
            format!("voice_identity:{}", &channel.id),
            // Draw consent dies with the voice state: an allowlist must not
            // outlive the call it was granted in (rev-3 review). Keyed by THIS
            // channel, so it is per-channel, not per-server.
            format!("annotations_allow:{}:{}", &channel.id, user_id),
            // KEYS[7..]: per-server, deleted with the pointer.
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
        ],
    }
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
/// Guarded by CHANNEL, not by connection: a late leave from the same channel
/// the user has since rejoined still clears it (pre-existing, out of scope).
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

/// The FALLBACK for [`delete_voice_state`], and ONLY that: the teardown
/// exactly as it was before [`DELETE_VOICE_STATE`] existed. Same keys, same
/// commands, and every per-server key deleted unconditionally.
///
/// Kept verbatim so a Redis that will not run the script degrades to the old
/// behavior rather than to a broken leave. Do not call it from anywhere else:
/// it deletes a newer channel's per-server state after a move, which is the
/// defect the script exists to fix. The reasons for each key are on
/// [`voice_state_teardown_input`].
async fn delete_voice_state_unconditionally(
    channel: &UserVoiceChannel,
    user_id: &str,
) -> Result<()> {
    let unique_key = format!(
        "{}:{}",
        &user_id,
        channel.server_id.as_ref().unwrap_or(&channel.id)
    );

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

    for user_id in user_ids {
        let unique_key = format!("{user_id}:{parent_id}");

        pipeline.srem(format!("vc:{user_id}"), channel).del(&[
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            format!("screen_video:{unique_key}"),
            format!("recording:{unique_key}"),
            format!("rc_capable:{unique_key}"),
            format!("watching:{unique_key}"),
            // Draw consent dies with the call (rev-3 review).
            format!("annotations_allow:{}:{}", &channel.id, user_id),
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
/// The two non-`Moved` arms are ordinary outcomes, not failures: the callers
/// that matter are a moderator route (where "they already left" is a no-op,
/// not a 500) and the AFK sweep (which runs on a timer against a population
/// that is shifting under it). Raising on either would turn a lost race into
/// an error the caller has to special-case back into success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoiceMoveOutcome {
    /// The target was moved. `node` is the LiveKit node the destination room
    /// lives on, `from` the channel they were pulled out of.
    ///
    /// Precisely: ONE connection of theirs — the one chosen from the SFU's
    /// participant list for `from`, which the minted token and the event both
    /// name — is now addressed to the destination, and every connection that
    /// list reported for that account in `from` was removed from it (the
    /// moved one included; "already gone" counts as removed). Any other
    /// connection was therefore ejected from the call rather than moved. An
    /// account normally holds exactly one, so normally those are the same
    /// sentence; they come apart when two sessions raced the join front door,
    /// and the eviction leg of `move_user_to_voice_channel` says why that
    /// resolves this way.
    ///
    /// There is no degraded path behind this variant: a listing that fails
    /// fails the move before anything is written, and a real failure to
    /// remove any LISTED connection is returned as an error (only a derived,
    /// unlisted screen leg is best-effort), so `Moved` is only ever reported
    /// for a move whose every listed connection was removed or already gone.
    /// The variant carries no eviction count on purpose — it is a transport
    /// detail no caller can act on.
    Moved { node: String, from: String },
    /// The target holds no voice state in the destination's server; or the
    /// channel they are recorded in has no LiveKit node behind it any more;
    /// or the SFU says that room does not exist, or lists no connection of
    /// theirs in it. Always answered before the move writes anything.
    NotConnected,
    /// The target is already sitting in the destination.
    AlreadyPresent,
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

async fn admit_voice_move(
    db: &Database,
    target: &User,
    destination: &Channel,
) -> Result<VoiceMoveAdmission> {
    // Server channels only. This is the one thing keeping the move primitive
    // off DMs and Groups, both of which report `server() == None` — and a DM
    // is an E2EE two-seat call that nothing may drag a third party into.
    if destination.server().is_none() {
        return Err(create_error!(UnknownChannel));
    }

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

    // `ViewChannel` is required alongside `Connect`, and it is about what
    // happens AFTER the move lands rather than about the move itself: bonfire
    // filters a channel the user cannot view out of `Ready`, so the client's
    // `channels.get(to)` comes back undefined and the move UI tells them to
    // open a channel that structurally is not there — out of the call they
    // were in, with no route back.
    //
    // A move is not a join: the target never chose this destination, so the
    // gate has to hold for them rather than merely be representable to them.
    // As the calculus stands today this is implied: the server-channel arm
    // revokes every bit once `ViewChannel` is missing, so this adds no
    // refusal that `Connect` does not already produce. It is here to state
    // the rule the client behavior actually depends on, and to keep the
    // gate correct if that implication ever stops holding.
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    // The same occupancy cap the join front door enforces, with the same
    // `ManageChannel` exemption. Without it a move walks straight past a
    // limit a join is refused at — and since the route skips its
    // `MoveMembers` check when you move YOURSELF, that was reachable by any
    // member, not just a moderator.
    //
    // Only difference from the join leg: the members read is skipped when
    // the channel has no cap, because there is nothing to compare it to.
    //
    // The decision itself lives in `occupancy_cap_refuses`, which carries the
    // already-present exemption the other two caps have always had. `None`
    // here still means "no roster recorded", which is not a full room.
    if let Some(max_users) = voice_info.max_users {
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

/// Every refusal a voice move can raise, with no side effects, so a caller
/// can run them before it mutates anything.
///
/// `move_user_to_voice_channel` runs the identical set — it goes through the
/// same `admit_voice_move` and the same `assert_call_caps_admit` — so this is
/// a pre-flight, never a substitute for it. Nothing here is a TOCTOU-free
/// promise: the caps in particular are check-then-act, with the voice-ingress
/// backstop closing the admission race.
pub async fn assert_voice_move_admissible(
    db: &Database,
    target: &User,
    destination: &Channel,
) -> Result<()> {
    admit_voice_move(db, target, destination).await?;

    // Call-admission caps (D12 video-participant cap + T-20 MLS SFU-token
    // coupling), enforced against the DESTINATION for the TARGET. A
    // privileged door must not bypass a cap the front door enforces.
    assert_call_caps_admit(db, &UserVoiceChannel::from_channel(destination), &target.id).await
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
/// Legs are emitted BEFORE their primary, the order `remove_user` already uses:
/// the leg is a helper of the primary, and tearing the owner down first is what
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

/// Which of the target's connections in the source room a move MOVES.
///
/// `participants` is the SFU's own list for the source room;
/// `mapped_identity` is what `voice_identity:{from}` names for the target, if
/// anything. A candidate is a PRIMARY of the target — its identity's user
/// segment is `target_id` and it is not a screen leg (a leg is a helper of
/// its owner and is never the thing that moves). Among candidates, in order:
///
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
    mapped_identity: Option<&str>,
) -> Option<&'a ParticipantInfo> {
    let primaries = participants.iter().filter(|participant| {
        user_id_from_participant_identity(&participant.identity) == target_id
            && !is_screen_leg(&participant.identity)
    });

    if let Some(mapped) = mapped_identity {
        if let Some(listed) = primaries
            .clone()
            .find(|participant| participant.identity == mapped)
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

/// Move `target` into `destination`, server-authoritatively.
///
/// FOUR ARGUMENTS, ALL DAEMON-CONSTRUCTIBLE, AND DELIBERATELY SO. There is no
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
/// Moves the target from wherever they are in the destination's server. A
/// caller whose decision was made about one particular source channel uses
/// [`move_user_to_voice_channel_expecting`] instead, and today both
/// production callers do: the moderator route (`member_edit`, since AFK
/// Stage 6 F-A3) and the AFK sweep. This four-argument form has no
/// production caller left.
pub async fn move_user_to_voice_channel(
    db: &Database,
    voice_client: &VoiceClient,
    target: &User,
    destination: &Channel,
) -> Result<VoiceMoveOutcome> {
    move_user_to_voice_channel_expecting(db, voice_client, target, destination, None).await
}

/// Whether the target has left the source channel a caller decided about:
/// `expected_from` names that channel (`None` = no expectation), `from` is
/// what the `{user}:{server}` pointer names now.
fn source_moved_on(expected_from: Option<&str>, from: &str) -> bool {
    expected_from.is_some_and(|expected| expected != from)
}

/// [`move_user_to_voice_channel`], for a caller that decided the move about a
/// particular SOURCE channel (Wave 5b-2 audit A2).
///
/// The AFK sweep decides from an idle claim naming the channel the member was
/// idle in, and between that read and this call the member may deliberately
/// switch to another channel of the server. Without an expectation the move
/// re-derives `from` from the pointer and moves them out of the channel they
/// just chose. With `expected_from: Some(x)` a pointer that no longer names
/// `x` answers `NotConnected` BEFORE any listing, write or mint: from the
/// caller's point of view the member it meant is no longer connected there.
///
/// This narrows the window to the few reads between this check and the SFU
/// listing; it does not close it. `None` behaves exactly as
/// [`move_user_to_voice_channel`], which is implemented by calling this.
pub async fn move_user_to_voice_channel_expecting(
    db: &Database,
    voice_client: &VoiceClient,
    target: &User,
    destination: &Channel,
    expected_from: Option<&str>,
) -> Result<VoiceMoveOutcome> {
    // Derived here, never passed in, for the reason in
    // `move_user_to_voice_channel`'s doc comment — and derived BEFORE
    // admission rather than taken out of it, so that the "they are already
    // there" answer below can be given without running any admission work at
    // all. A DM or a Group still cannot reach a line past this point.
    let Some(server_id) = destination.server() else {
        return Err(create_error!(UnknownChannel));
    };

    let Some(from) = get_user_voice_channel_in_server(&target.id, server_id).await? else {
        return Ok(VoiceMoveOutcome::NotConnected);
    };

    // The caller's source is gone (see the doc comment): nothing listed,
    // written or minted. First of all the answers, ahead of the source ==
    // destination guard as well: whatever else is true, the premise the
    // caller decided on no longer holds.
    if source_moved_on(expected_from, &from) {
        return Ok(VoiceMoveOutcome::NotConnected);
    }

    // Source == destination. Without this the code below evicts the target
    // from the very room it is putting them back into: every connection of
    // theirs that the SFU lists in `from` goes through
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

    let VoiceMoveAdmission { permissions } = admit_voice_move(db, target, destination).await?;

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

    let Some(moving) =
        select_move_connection(&participants, &target.id, mapped_identity.as_deref())
    else {
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
    // preference above. The device id is `moving`'s device suffix, so the
    // token is minted for its identity: a device-qualified seat keeps its
    // identity (and its E2EE device binding) across the move, and a bare seat
    // stays bare. The nonce is `moving`'s SOURCE nonce — never the new
    // token's, which is minted inside `create_token` below.
    let addressing = move_addressing(moving, &target.id);
    // And every connection that has to leave `from`, from the same list.
    let evictions = eviction_targets(
        participants
            .iter()
            .map(|participant| participant.identity.clone()),
        &target.id,
    );

    // First write. Everything above this line is side-effect free.
    if existing_node.is_none() {
        set_channel_node(destination.id(), &new_node).await?;
    }

    let source_channel = UserVoiceChannel {
        id: from.clone(),
        server_id: destination_channel.server_id.clone(),
    };

    voice_client.create_room(&new_node, destination).await?;

    // Minted for the connection chosen above: `addressing.device_id` is that
    // connection's device suffix (`None` for a bare seat), so the token's
    // identity is exactly the chosen one's. The event below carries the same
    // suffix plus the chosen connection's nonce, so the session this token
    // was minted for is the only one that redeems it — see the emit site.
    let token = voice_client
        .create_token(
            &new_node,
            db,
            target,
            permissions,
            destination,
            addressing.device_id.as_deref(),
        )
        .await?;

    // Remote-control release hook (plan §1): this path removes participants
    // from the SFU directly, bypassing `remove_user_from_voice_channel`, and
    // additionally re-tokens the target into a DIFFERENT room while any grant
    // stays keyed to the old channel — so it must release explicitly here.
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

    // The Join label (Wave 5b-2 M4-a). Written HERE, after the room, the
    // mint and the release and immediately before the emit, so a move that
    // fails before the target is sent anything leaves no marker to mislabel
    // their next ordinary join (it used to be written before `create_room`
    // and `create_token`, both behind a `?`). The evictions below can still
    // fail the move, but by then the token is out and the join it labels is
    // the one the move asked for.
    //
    // BEST-EFFORT, no `?`: by now the remote-control grant has been revoked,
    // and the marker only picks `VoiceChannelMove` over `VoiceChannelJoin`
    // for the destination's roster; the source's Leave is published
    // regardless. Failing the move over it would strand the target with a
    // revoked grant and no token.
    if let Err(error) = set_user_moved_to_voice(destination.id(), &source_channel, &target.id).await
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
    // This does not by itself close the race — the client half of it is an
    // acceptance window for a token that arrives just after a drop from
    // `from`. It removes the GUARANTEED loss and makes the ordinary path
    // work; the window is what covers the reordering being lost to
    // scheduling.
    //
    // THE ADDRESSING GATE. `private` reaches every session the target has,
    // so without one each session has only a local guess at whether the
    // token is its own — and the guess is satisfiable by an ordinary event,
    // so two sessions can reach for one single-mint token and the SFU evicts
    // whichever loses the duplicate-identity race. Both fields describe the
    // connection `select_move_connection` chose from the SFU's list:
    //
    // - `conn_nonce` IS the gate when present: that connection's `"conn"`
    //   token attribute, which names exactly one connection — including a
    //   bare seat, which a device id cannot name at all.
    // - `device_id` is EXACTLY the suffix handed to `create_token` above. It
    //   is the gate when the nonce is absent, and it drives the client's
    //   E2EE identity assertion either way.
    //
    // `None` for both is honest rather than permissive: the chosen
    // connection is bare and the SFU reported no nonce for it, and the client
    // is told so rather than left to assume the token is addressed to it.
    EventV1::UserMoveVoiceChannel {
        node: new_node.clone(),
        url,
        device_id: addressing.device_id,
        conn_nonce: addressing.conn_nonce,
        from: from.clone(),
        to: destination.id().to_string(),
        token,
    }
    .private(target.id.clone())
    .await;

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
    // source room. Absent from every roster, and unkickable — a second
    // `remove_user` resolves through the now-empty mapping to the bare user id
    // and no-ops against an SFU that knows a device-qualified one. So the SFU's
    // own participant list is the authority here; Redis cannot be.
    //
    // WHAT THE MOVED USER ACTUALLY LANDS AS. The token above was minted for
    // exactly ONE identity — the connection `select_move_connection` chose
    // from the SFU's list — and the event just emitted names that connection
    // by its nonce (and its device suffix), which is what tells a session
    // whether the token is addressed to it. So the honest description of
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

    Ok(VoiceMoveOutcome::Moved {
        node: new_node,
        from,
    })
}

/// What one member's permission sync amounted to, as the room-wide sync
/// records it (AFK Stage 6 F-A1).
#[derive(Debug, PartialEq, Eq)]
enum MemberSync<E> {
    /// The new grant reached the SFU, or there was nothing to push for this
    /// member (no voice state, or a role-scoped sync their roles do not
    /// reach).
    Synced,
    /// The member is no longer there to sync: the user or member document
    /// is gone, or the SFU has no such participant. Not a failure of the
    /// room-wide sync. Carries the error [`sync_user_voice_permissions`]
    /// has always returned for it, which that single-user entry point still
    /// returns.
    Gone(E),
    /// Anything else.
    Failed(E),
}

/// Sync every member in `members`, in order, and record each outcome.
///
/// The loop has no early exit: the per-member call returns a [`MemberSync`],
/// not a `Result`, so there is no `?` to put on it, and one member's failure
/// is recorded and logged while the rest are still synced.
/// [`member_sync_result`] decides afterwards what the outcomes amount to.
/// Generic over the per-member call so the tests drive THIS loop with a fake
/// one; [`sync_voice_permissions`] hands it the real one.
async fn sync_each_member<E, F, Fut>(
    channel_id: &str,
    members: Vec<String>,
    mut sync_one: F,
) -> Vec<MemberSync<E>>
where
    E: std::fmt::Debug,
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = MemberSync<E>>,
{
    let mut outcomes = Vec::with_capacity(members.len());

    for user_id in members {
        let outcome = sync_one(user_id.clone()).await;

        match &outcome {
            MemberSync::Synced => {}
            MemberSync::Gone(_) => log::debug!(
                "permission sync of {channel_id}: skipped {user_id}, who is no longer there"
            ),
            MemberSync::Failed(error) => log::warn!(
                "permission sync of {channel_id}: failed for {user_id}, the remaining members \
                 are still synced: {error:?}"
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
/// Callers: `sync_afk_designation_change`, and the role and permission
/// routes (`roles_edit`, `roles_delete`, `roles_edit_positions`, both
/// `permissions_set` and both `permissions_set_default`). Each of them calls
/// this last, after its own write, with `?`: none acts on a partial sync,
/// so trying every member before answering changes nothing for them except
/// that later members are no longer left behind.
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

    let outcomes = sync_each_member(channel.id(), members, move |user_id| async move {
        sync_member_voice_permissions(db, voice_client, node, &user_id, channel, server, role_id)
            .await
    })
    .await;

    member_sync_result(outcomes)
}

/// One member of a room-wide sync, by user id, classified for
/// [`member_sync_result`].
async fn sync_member_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user_id: &str,
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

    sync_user_voice_permissions_classified(db, voice_client, node, &user, channel, server, role_id)
        .await
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
/// - the revision-70 migration (the "afk"-named-channel backfill), which runs
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
/// matching `roles_edit.rs` and both `permissions_set.rs` call sites, but
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
/// to a role the way the `roles_edit` and `permissions_set` syncs are.
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

    fn chosen(
        participants: &[super::ParticipantInfo],
        target: &str,
        mapped: Option<&str>,
    ) -> Option<String> {
        super::select_move_connection(participants, target, mapped)
            .map(|participant| participant.identity.clone())
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
    /// A2); `move_user_to_voice_channel` only delegates to it, and
    /// `the_plain_move_delegates_with_no_expectation` pins that it does
    /// nothing else. Every pin that reads this therefore reads the one body
    /// every move runs, through either entry point.
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
            .unwrap_or_else(|| panic!("`move_user_to_voice_channel` no longer calls `{needle}`"))
    }

    /// P-3: the SFU listing precedes EVERY write and the mint. A listing
    /// after `set_channel_node` or the `moved_to` marker would let a
    /// `NotConnected` (or a failed list) leave them standing, the marker to
    /// relabel the target's next Join; after the mint, a stale mapping would
    /// address the token to a connection that is gone.
    #[test]
    fn the_move_lists_the_source_room_before_any_write() {
        let body = move_body_code();
        let list = first(&body, "list_participants_if_present(");

        for write in [
            "set_channel_node(",
            "set_user_moved_to_voice(",
            "create_room(",
            ".create_token(",
        ] {
            assert!(
                list < first(&body, write),
                "`list_participants_if_present(` must precede `{write}` in \
                 `move_user_to_voice_channel` — a refusal, a gone room or a \
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
        let emit = first(&flat, ".private(target.id");

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

    /// I-19 (Wave 5b-2): the move itself has no bot check. Bots can be in
    /// voice and a moderator may move one; the AFK route refuses bots and the
    /// sweep skips them, each at its own layer. A bot check here would make
    /// the moderator route refuse a move it allows today.
    #[test]
    fn the_move_does_not_look_at_bots() {
        let body = move_body_code();

        assert!(
            !body.contains(".bot"),
            "`move_user_to_voice_channel` reads `.bot` — the bot policy \
             belongs to its callers, not to the move"
        );
    }

    /// A2 (5b-2.1 audit): the expectation, by value. No expectation never
    /// refuses; an expectation refuses exactly when the pointer names some
    /// other channel.
    #[test]
    fn a_move_expecting_a_source_refuses_only_when_the_pointer_left_it() {
        use super::source_moved_on;

        assert!(!source_moved_on(None, "A"), "no expectation, no refusal");
        assert!(!source_moved_on(Some("A"), "A"), "still in the source");
        assert!(
            source_moved_on(Some("A"), "B"),
            "moved on to another channel"
        );
    }

    /// A2 (5b-2.1 audit): the expectation is checked right after the pointer
    /// is read and BEFORE anything else the move does, so a member who moved
    /// on is answered `NotConnected` with nothing listed, admitted, written,
    /// minted or emitted. Mutations: the check deleted, its `return` changed,
    /// or the check moved below the listing or any write.
    #[test]
    fn the_move_checks_its_expected_source_before_anything_else() {
        let body = move_body_code();
        let flat = body.split_whitespace().collect::<Vec<_>>().join(" ");

        const CHECK: &str = "if source_moved_on(expected_from, &from) \u{7b} \
                             return Ok(VoiceMoveOutcome::NotConnected); \u{7d}";
        assert_eq!(
            flat.matches(CHECK).count(),
            1,
            "the move must check its expected source exactly once, answering \
             `NotConnected`: {flat}"
        );
        let check = first(&flat, CHECK);

        assert!(
            first(&flat, "let Some(from) = get_user_voice_channel_in_server(") < check,
            "the check compares against the pointer, so it follows the read"
        );
        for later in [
            "if from == destination.id()",
            "admit_voice_move(",
            "list_participants_if_present(",
            "set_channel_node(",
            "create_room(",
            ".create_token(",
            "release_remote_control_for_user(",
            "set_user_moved_to_voice(",
            ".private(target.id",
            "remove_identity_if_present(",
        ] {
            assert!(
                check < first(&flat, later),
                "the expected-source check must precede `{later}`"
            );
        }
    }

    /// A2 (5b-2.1 audit): the four-argument move keeps its signature and is
    /// exactly a delegation with no expectation. No production code calls it
    /// any more: since AFK Stage 6 F-A3 the moderator route (`member_edit`)
    /// calls `move_user_to_voice_channel_expecting` with the source it
    /// authorized, as the AFK sweep already did. Mutations: an expectation
    /// passed (`Some(..)`), or any other statement added to its body.
    #[test]
    fn the_plain_move_delegates_with_no_expectation() {
        let shipping = this_file_shipping();

        assert!(
            shipping.contains(
                "pub async fn move_user_to_voice_channel(\n    db: &Database,\n    \
                 voice_client: &VoiceClient,\n    target: &User,\n    \
                 destination: &Channel,\n) -> Result<VoiceMoveOutcome> \u{7b}"
            ),
            "`move_user_to_voice_channel` must keep its four-argument signature"
        );
        let body = flat_fn_body(&shipping, "pub async fn move_user_to_voice_channel(");
        assert_eq!(
            body.trim(),
            "move_user_to_voice_channel_expecting(db, voice_client, target, destination, None).await",
            "`move_user_to_voice_channel` must only delegate, with no expectation"
        );
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
    /// its NotFound classification is left in the move.
    #[test]
    fn the_move_emits_before_it_evicts_and_only_through_the_listing() {
        let body = move_body_code();

        assert!(
            first(&body, ".private(target.id") < first(&body, "remove_identity_if_present("),
            "the move event must be emitted BEFORE the first removal: a Leave \
             reaches the client ahead of a later event, and a client already \
             out of CONNECTED drops its own move"
        );

        for banned in ["remove_user(", "remove_identity("] {
            assert!(
                !body.contains(banned),
                "`move_user_to_voice_channel` calls `{banned}` — it must evict \
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

    /// B-1 + M-4: both addressing fields of the move event, and the device
    /// the token is minted for, come from ONE `move_addressing` call on the
    /// connection `select_move_connection` chose. Each revert this guards is
    /// a one-token edit that compiles and fails nothing else: `conn_nonce:
    /// None` switches the client's nonce gate off on every seat, and a
    /// `device_id` from the Redis mapping addresses a connection the SFU no
    /// longer lists.
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

        assert!(
            flat.contains(
                "let Some(moving) = select_move_connection(&participants, &target.id, \
                 mapped_identity.as_deref())"
            ),
            "`moving` must be the connection chosen from the SFU's list"
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
            "the addressing must exist before the token is minted from it"
        );

        // The token is minted for the addressed device.
        let mint = first(&flat, ".create_token(");
        let mint_args = &flat[mint..mint + first(&flat[mint..], ".await?")];
        assert!(
            mint_args.contains("addressing.device_id.as_deref()"),
            "the token must be minted for `addressing.device_id`: {mint_args}"
        );

        // The event literal's two addressing fields, and nothing else feeding
        // them.
        let literal_at = first(&flat, "EventV1::UserMoveVoiceChannel");
        let open = literal_at + first(&flat[literal_at..], "\u{7b}");
        let literal = braced_body(&flat, open);
        let fields: Vec<&str> = literal.split(',').map(str::trim).collect();
        assert!(
            fields.contains(&"device_id: addressing.device_id"),
            "the event's `device_id` must be `addressing.device_id`: {literal}"
        );
        assert!(
            fields.contains(&"conn_nonce: addressing.conn_nonce"),
            "the event's `conn_nonce` must be `addressing.conn_nonce`: {literal}"
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
    #[test]
    fn the_room_sync_tries_every_member_before_deciding() {
        let shipping = this_file_shipping();

        let room = flat_fn_body(&shipping, "pub async fn sync_voice_permissions(");
        assert!(
            room.contains(
                "let outcomes = sync_each_member(channel.id(), members, move |user_id| async move \
                 \u{7b} sync_member_voice_permissions(db, voice_client, node, &user_id, channel, \
                 server, role_id) .await \u{7d}) .await;"
            ),
            "`sync_voice_permissions` must walk the room through `sync_each_member`, \
             with no `?` on the per-member call: {room}"
        );
        assert!(
            room.ends_with(
                "let outcomes = sync_each_member(channel.id(), members, move |user_id| async move \
                 \u{7b} sync_member_voice_permissions(db, voice_client, node, &user_id, channel, \
                 server, role_id) .await \u{7d}) .await; member_sync_result(outcomes)"
            ),
            "every outcome must go to `member_sync_result`, and its answer is the \
             function's: {room}"
        );
        assert!(
            !room.contains("sync_user_voice_permissions("),
            "the room sync must not call the single-user entry point, whose \
             `Err` for a gone member would fail the room: {room}"
        );

        let each = flat_fn_body(&shipping, "async fn sync_each_member<");
        let loop_at = first(&each, "for user_id in members");
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
                "let pushed = voice_client .update_permissions_if_present( node, user, \
                 channel_id, voice_participant_permissions(can_listen, &allowed_sources), ) \
                 .await?; if !pushed \u{7b} return Ok(MemberSync::Gone(create_error!(InternalError))); \u{7d}"
            ),
            "a participant the SFU no longer has is skipped: {push}"
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
            sync_member_voice_permissions, sync_user_voice_permissions, MemberSync, VoiceClient,
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

        // A user who is not (or no longer) a member of the server.
        let stranger = User::create(&db, "SyncGoneStranger".to_string(), None, None)
            .await
            .expect("`User`");
        match sync_member_voice_permissions(
            &db,
            &voice_client,
            "node",
            &stranger.id,
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
    #[test]
    fn delete_voice_state_script_source_is_pinned() {
        let expected = [
            "",
            "redis.call('SREM', KEYS[2], ARGV[2])",
            "redis.call('SREM', KEYS[3], ARGV[3])",
            "redis.call('HDEL', KEYS[4], ARGV[2])",
            "redis.call('HDEL', KEYS[5], ARGV[2])",
            "redis.call('DEL', KEYS[6])",
            "local pointer = redis.call('GET', KEYS[1])",
            "if pointer and pointer ~= ARGV[1] then",
            "    return 0",
            "end",
            "redis.call('DEL', KEYS[1], unpack(KEYS, 7))",
            "return 1",
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
                    "joined_at:USER:SRV",          // KEYS[7..], the flags
                    "is_publishing:USER:SRV",
                    "is_receiving:USER:SRV",
                    "screensharing:USER:SRV",
                    "camera:USER:SRV",
                    "screen_video:USER:SRV",
                    "recording:USER:SRV",
                    "rc_capable:USER:SRV",
                    "watching:USER:SRV",
                ]),
                // ARGV[1] the channel, ARGV[2] the user, ARGV[3] the `vc:` member
                args: strings(&["CHAN", "USER", "CHAN-SRV"]),
            }
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
        assert_eq!(input.keys[6], "joined_at:USER:DM");
        assert_eq!(input.args, strings(&["DM", "USER", "DM"]));
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
        assert_eq!(
            call_sites(&shipping, "delete_voice_state_unconditionally(").len(),
            1,
            "the unconditional teardown is the script's fallback and nothing \
             else: it wipes a newer channel's per-server state after a move"
        );

        // The fallback is the pre-script delete set, every key unconditional.
        let fallback = flat_fn_body(&shipping, "async fn delete_voice_state_unconditionally(");
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
            // `strip_test_items` brace-matches this module out of its own
            // scan, and a lone brace here would silently over-strip the file.
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

    /// Remove every `#[cfg(test)]`-gated item from `source` so the scans
    /// below see only code that ships. Matching is TEXTUAL: the attribute,
    /// then either a brace-matched body or a bodyless item ending in `;`
    /// (trait method declarations). Test-module authors must therefore keep
    /// braces BALANCED inside test-code strings and comments — no unpaired
    /// brace characters, no format escape without its counterpart. Getting
    /// that wrong cannot pass silently: both scans below assert their known
    /// call sites are FOUND, so an over-strip that eats shipping code fails
    /// the run.
    ///
    /// Audit LOW-2 (wave-3 completion audit): an item whose braces never
    /// balance used to run silently to EOF, which SILENTLY DELETES every
    /// shipping line below it — in this file, the entire second half. A
    /// scanner that truncates on malformed input is a false-PASS generator,
    /// so it now panics instead, naming the file and what to do about it.
    fn strip_test_items(rel: &str, source: &str) -> String {
        const ATTR: &str = "#[cfg(test)]";
        let mut shipping = String::with_capacity(source.len());
        let mut rest = source;
        while let Some(attr) = rest.find(ATTR) {
            shipping.push_str(&rest[..attr]);
            let after = &rest[attr + ATTR.len()..];

            let mut depth = 0i64;
            let mut item_end = None;
            for (i, ch) in after.char_indices() {
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
                     of file. Either a brace is genuinely unbalanced, or a \
                     test string or comment contains an unpaired brace (write \
                     it as the \\u escape instead). Truncating here would \
                     silently delete every shipping line below it from this \
                     scan"
                )
            });
            rest = &after[item_end..];
        }
        shipping.push_str(rest);
        shipping
    }

    /// Every shipping Rust source in the workspace, as
    /// (crates/-relative path, cfg(test)-stripped text).
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
                let shipping = strip_test_items(&rel, &text);
                (rel, shipping)
            })
            .collect()
    }

    /// Byte offsets of call sites of `needle` (an identifier followed by
    /// `(`) in stripped source — the definition line, `use` imports, and
    /// comment lines are not callers.
    fn call_sites(shipping: &str, needle: &str) -> Vec<usize> {
        shipping
            .match_indices(needle)
            .map(|(at, _)| at)
            .filter(|at| {
                let line_start = shipping[..*at].rfind('\n').map_or(0, |nl| nl + 1);
                let before_match = &shipping[line_start..*at];
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

    /// The argument text of a call whose opening `(` sits at byte `open`,
    /// exclusive of the parentheses themselves. Same textual, paren-matching
    /// discipline as `strip_test_items`: callers must keep parentheses
    /// BALANCED inside strings and comments in the code being scanned.
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
        const PUSHES: [&str; 4] = [
            ".update_permissions(",
            ".update_permissions_identity(",
            ".update_permissions_if_present(",
            ".update_permissions_identity_if_present(",
        ];
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
        for (rel, shipping) in &sources {
            if rel == TRANSPORT_FILE {
                saw_transport = true;
                continue;
            }
            for needle in PUSHES {
                for (at, _) in shipping.match_indices(needle) {
                    // The permission argument lives inside this call's
                    // parentheses; classify by which constructor appears
                    // there. Same textual-matching discipline as
                    // strip_test_items.
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
    /// exclusive of the braces themselves. Same textual, brace-matching
    /// discipline as `strip_test_items`: callers must keep braces BALANCED
    /// inside strings and comments in the code being scanned.
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
        // The opening brace is written as an escape so `strip_test_items`,
        // which brace-matches this very module to cut it out of the scan,
        // still sees balanced braces here. A bare opening brace in a string
        // literal inside a test module silently over-strips the file and breaks
        // the sibling contract tests - which is exactly what it did.
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
        // gate scan below writes its one that way: `strip_test_items`
        // brace-matches this very module out of its own scan.
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
    /// `move_is_refused_when_the_mover_is_denied_the_source` cover those,
    /// wherever the route harness can run.
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
        // that way: `strip_test_items` brace-matches this very module to cut
        // it out of the scan, and a lone brace here silently over-strips the
        // file and breaks every sibling contract test.
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
    /// channel pull members OUT of it into a channel they do control, and
    /// distinguish `NotConnected` from a success to learn who was in it. The
    /// server-scoped `MoveMembers` check reads no channel override at either
    /// end, so the reasoning is symmetric and so is the gate.
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
    // `move_user_to_voice_channel`, against a real database and the real
    // permission calculus. They stop short of the call-admission caps and of
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

            // Control: the same member, the same server, a real voice
            // channel — admissible. So the refusal below is about the channel
            // type and nothing else.
            super::admit_voice_move(&db, &member_user, &voice)
                .await
                .expect("control: a plain member may be moved into a voice channel");

            let refused = super::admit_voice_move(&db, &member_user, &text)
                .await
                .expect_err("a text channel is not somewhere anyone can be moved");
            assert!(
                matches!(refused.error_type, ErrorType::NotAVoiceChannel),
                "expected NotAVoiceChannel, got {:?}",
                refused.error_type
            );
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

            // Control, before the override: the member is admissible, so the
            // refusal below is the override doing the work.
            super::admit_voice_move(&db, &member_user, &destination)
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

            let refused = super::admit_voice_move(&db, &member_user, &destination)
                .await
                .expect_err("the TARGET is denied Connect on the destination");
            assert!(
                matches!(refused.error_type, ErrorType::MissingPermission { .. }),
                "expected MissingPermission, got {:?}",
                refused.error_type
            );
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

            // Control, before the override: admissible, so the refusal below
            // is the override doing the work.
            super::admit_voice_move(&db, &member_user, &destination)
                .await
                .expect("control: the member may be moved here before the denial");

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

            let refused = super::admit_voice_move(&db, &member_user, &destination)
                .await
                .expect_err("the TARGET cannot view the destination");
            assert!(
                matches!(refused.error_type, ErrorType::MissingPermission { .. }),
                "expected MissingPermission, got {:?}",
                refused.error_type
            );
        });
    }
}

/// Re-sync one user's LiveKit grant in `channel`.
///
/// A member who has gone (the member document is deleted, or the SFU has no
/// such participant) is still an `Err` here, of the same type as before AFK
/// Stage 6 F-A1 (`NotFound`, `InternalError`): this single-user entry point
/// keeps its contract for its direct caller (`member_edit`). The room-wide
/// [`sync_voice_permissions`] uses the classified form and skips such a
/// member instead. A real SFU failure on the push is still logged at ERROR
/// and reported to Sentry (`update_permissions_identity_if_present`).
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
async fn sync_user_voice_permissions_classified(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user: &User,
    channel: &Channel,
    server: Option<&Server>,
    role_id: Option<&str>,
) -> MemberSync<revolt_result::Error> {
    match push_user_voice_permissions(db, voice_client, node, user, channel, server, role_id).await
    {
        Ok(outcome) => outcome,
        Err(error) => MemberSync::Failed(error),
    }
}

/// The body of [`sync_user_voice_permissions`]. Every `?` in it is a real
/// failure; the two ways a member can be gone are returned as
/// `Ok(MemberSync::Gone(..))`, each at the step that finds it out.
async fn push_user_voice_permissions(
    db: &Database,
    voice_client: &VoiceClient,
    node: &str,
    user: &User,
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

        let Some(voice_state) = get_voice_state(&user_voice_channel, &user.id).await? else {
            return Ok(MemberSync::Synced);
        };

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
        let before = roster_baseline(&user.id);
        let update_event = roster_flags(&user.id, &allowed_sources, &voice_state);

        update_voice_state(&user_voice_channel, &user.id, &update_event).await?;

        // The SFU reporting no such participant means the connection is
        // already gone: no grant is left to correct, so the member is skipped
        // rather than failing the sync (F-A1). It stops here, as the old `?`
        // on this push stopped it, before the remote-control release and the
        // fan-out.
        let pushed = voice_client
            .update_permissions_if_present(
                node,
                user,
                channel_id,
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
    /// clears, beyond the two `create_voice_state` already writes.
    async fn seed_per_channel_voice_state(conn: &mut Conn, channel: &UserVoiceChannel, user: &str) {
        let _: () = conn
            .hset(format!("vc_leg:{}", channel.id), user, "SID")
            .await
            .unwrap();
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

        assert_eq!(
            (member, listed, leg, identity, annotations),
            (false, false, false, false, false),
            "{case}: per-channel state must go unconditionally \
             (vc_members, vc:, vc_leg, voice_identity, annotations_allow)"
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
        assert!(
            still_in_destination && destination_identity,
            "a leave from the source must not touch the destination's per-channel state"
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
}
