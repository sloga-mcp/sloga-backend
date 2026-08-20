//! Watch-together session state (watch-together plan §1).
//!
//! ONE session per voice channel, in Redis next to the voice state: the
//! host's control state (item, playing, position, rate) that every viewer's
//! client converges on. Sloga stores ONLY this control state — never media;
//! each viewer fetches the video from the provider (YouTube embed, their
//! own Jellyfin) on their own machine.
//!
//! Write discipline (plan §1, rev 3):
//! - `seq` comes from `INCR watch_seq:{channel}` so concurrent writers (host
//!   heartbeat + a moderator's pause) never mint the same number; receivers
//!   drop anything ≤ the last `seq` they applied for the same session `id`.
//! - Every host write carries the FULL host-owned state, so an interleaved
//!   heartbeat cannot roll a control change back for longer than one write.
//!   No Lua / WATCH — the repo has none and this is enough.
//! - Creation is `SET NX EX` (the remote-control offer rule: one atomic
//!   command, never SETNX-then-EXPIRE).
//!
//! Expiry: passive TTL, refreshed by every write. It is GARBAGE COLLECTION
//! behind the lifecycle teardown (`delete_voice_state` ends the session when
//! the host's voice state goes), not enforcement — an expiring key fires no
//! event, so the client also treats "no update for > 60 s while playing" as
//! host-unreachable and re-GETs.

use redis_kiss::AsyncCommands;
use revolt_models::v0::{WatchMedia, WatchSession, WATCH_RATE_NORMAL_PERMILLE};
use revolt_result::{Result, ToRevoltError};

use crate::events::client::EventV1;

use super::{get_connection, get_voice_channel_members, UserVoiceChannel};

/// Session lifetime without a write. The host heartbeats every 5 s, so this
/// is ~180 missed heartbeats — a wedged client, not a slow one.
pub const WATCH_SESSION_TTL_SECS: usize = 15 * 60;

fn session_key(channel_id: &str) -> String {
    format!("watch_session:{channel_id}")
}

fn seq_key(channel_id: &str) -> String {
    format!("watch_seq:{channel_id}")
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn next_seq(conn: &mut redis_kiss::Conn, channel_id: &str) -> Result<u64> {
    let seq: u64 = conn.incr(seq_key(channel_id), 1u64).await.to_internal_error()?;
    // Keep the counter's lifetime tied to the session's: a counter that
    // outlives the session by the same TTL is harmless (monotonic across a
    // restart is a feature), an immortal one is litter.
    let _: () = conn
        .expire(seq_key(channel_id), WATCH_SESSION_TTL_SECS)
        .await
        .to_internal_error()?;
    Ok(seq)
}

/// Create the channel's session with `host_id` as host, paused at 0.
/// Returns `None` when a session already exists (`SET NX` lost).
pub async fn create_watch_session(
    channel_id: &str,
    host_id: &str,
    media: WatchMedia,
) -> Result<Option<WatchSession>> {
    use redis_kiss::redis::{ExistenceCheck, SetExpiry, SetOptions};

    let mut conn = get_connection().await?;
    let now = now_ms();
    let seq = next_seq(&mut conn, channel_id).await?;
    let session = WatchSession {
        id: ulid::Ulid::new().to_string(),
        channel_id: channel_id.to_string(),
        host_id: host_id.to_string(),
        media,
        playing: false,
        position_ms: 0,
        position_at: now,
        rate_permille: WATCH_RATE_NORMAL_PERMILLE,
        seq,
        started_at: now,
    };
    let serialized = serde_json::to_string(&session).to_internal_error()?;
    let stored: Option<String> = conn
        .set_options(
            session_key(channel_id),
            serialized,
            SetOptions::default()
                .conditional_set(ExistenceCheck::NX)
                .with_expiration(SetExpiry::EX(WATCH_SESSION_TTL_SECS)),
        )
        .await
        .to_internal_error()?;
    Ok(stored.map(|_| session))
}

pub async fn fetch_watch_session(channel_id: &str) -> Result<Option<WatchSession>> {
    let mut conn = get_connection().await?;
    let raw: Option<String> = conn.get(session_key(channel_id)).await.to_internal_error()?;
    let Some(raw) = raw else { return Ok(None) };
    match serde_json::from_str::<WatchSession>(&raw) {
        Ok(session) => Ok(Some(session)),
        Err(error) => {
            // A key this binary cannot read (a shape change across a deploy)
            // must not wedge the channel until the TTL: `create` would 409
            // on it and `end` could never find a host to authorize. Drop it.
            log::warn!("watch: dropping undeserializable session for {channel_id}: {error}");
            let _: () = conn
                .del(&[session_key(channel_id), seq_key(channel_id)])
                .await
                .to_internal_error()?;
            Ok(None)
        }
    }
}

/// Apply a host-owned state change: `apply` mutates the stored session, then
/// the server stamps `position_at` and a fresh `seq`, rewrites the key and
/// refreshes the TTL. Returns `None` if there is no session.
pub async fn update_watch_session(
    channel_id: &str,
    apply: impl FnOnce(&mut WatchSession),
) -> Result<Option<WatchSession>> {
    let mut conn = get_connection().await?;
    let raw: Option<String> = conn.get(session_key(channel_id)).await.to_internal_error()?;
    let Some(mut session) = raw.and_then(|raw| serde_json::from_str::<WatchSession>(&raw).ok())
    else {
        return Ok(None);
    };
    apply(&mut session);
    session.position_at = now_ms();
    session.seq = next_seq(&mut conn, channel_id).await?;
    let serialized = serde_json::to_string(&session).to_internal_error()?;
    let _: () = conn
        .set_ex(session_key(channel_id), serialized, WATCH_SESSION_TTL_SECS)
        .await
        .to_internal_error()?;
    Ok(Some(session))
}

/// Remove the session (and its counter). Returns what was removed.
pub async fn delete_watch_session(channel_id: &str) -> Result<Option<WatchSession>> {
    let mut conn = get_connection().await?;
    let raw: Option<String> = conn.get(session_key(channel_id)).await.to_internal_error()?;
    let _: () = conn
        .del(&[session_key(channel_id), seq_key(channel_id)])
        .await
        .to_internal_error()?;
    Ok(raw.and_then(|raw| serde_json::from_str(&raw).ok()))
}

/// Fan the complete session to the call's members over private topics
/// (the `CallAnnotationConsent` shape — never the channel topic, whose
/// boundary is ViewChannel, not call membership). Sender included: the
/// host's other sessions need it too.
pub async fn fan_watch_update(channel: &UserVoiceChannel, session: &WatchSession) {
    if let Ok(Some(members)) = get_voice_channel_members(channel).await {
        for member_id in members {
            EventV1::WatchSessionUpdate {
                channel_id: channel.id.clone(),
                session: session.clone(),
            }
            .private(member_id)
            .await;
        }
    }
}

pub async fn fan_watch_end(channel: &UserVoiceChannel, session_id: &str) {
    if let Ok(Some(members)) = get_voice_channel_members(channel).await {
        for member_id in members {
            EventV1::WatchSessionEnd {
                channel_id: channel.id.clone(),
                id: session_id.to_string(),
            }
            .private(member_id)
            .await;
        }
    }
}

/// Lifecycle hook: the host's voice state is going away → the session ends.
/// Called from `delete_voice_state` BEFORE the member is removed from
/// `vc_members`, so the departing host's own sessions still get the end
/// event. Every leave path (ingress `participant_left`, forbidden-track
/// eject, delta kick/ban/server-delete/bot-delete, the reconciler) passes
/// through that one function — this is the chokepoint the plan names.
/// Best-effort: a Redis hiccup must not break the leave itself.
pub async fn end_watch_session_if_host(channel: &UserVoiceChannel, user_id: &str) {
    match fetch_watch_session(&channel.id).await {
        Ok(Some(session)) if session.host_id == user_id => {
            if let Err(error) = delete_watch_session(&channel.id).await {
                log::warn!("watch: failed to end session on host leave in {}: {error:?}", channel.id);
            }
            fan_watch_end(channel, &session.id).await;
        }
        Ok(_) => {}
        Err(error) => log::warn!("watch: session probe failed for {}: {error:?}", channel.id),
    }
}

/// Lifecycle hook: the whole call is being torn down.
pub async fn end_watch_session_for_channel(channel: &UserVoiceChannel) {
    match delete_watch_session(&channel.id).await {
        Ok(Some(session)) => fan_watch_end(channel, &session.id).await,
        Ok(None) => {}
        Err(error) => log::warn!("watch: failed to end session for {}: {error:?}", channel.id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revolt_models::v0::WatchMedia;

    /// One runtime shared by every Redis-backed test in this module — same
    /// rationale as the voice/mod.rs tests: `redis_kiss` pools connections
    /// in a GLOBAL mobc pool, and a connection created on one
    /// per-test runtime dies with it, poisoning the next test's draw.
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

    fn media() -> WatchMedia {
        WatchMedia::YouTube {
            video_id: "YE7VzlLtp-4".to_string(),
            title: None,
        }
    }

    /// TTL discipline (plan §1): create arms the TTL, every write re-arms
    /// it, and a lapsed session is simply GONE — fetch reports None
    /// (passive GC, no event) and the channel is free for a fresh create
    /// rather than wedged on a stale key until an operator intervenes.
    #[test]
    fn watch_session_ttl_expiry() {
        rt().block_on(ttl_case())
    }

    async fn ttl_case() {
        // Unique id so parallel runs against the shared Redis don't collide.
        let channel_id = ulid::Ulid::new().to_string();
        let created = create_watch_session(&channel_id, "host", media())
            .await
            .expect("create")
            .expect("fresh channel must accept a session");

        let mut conn = get_connection().await.expect("redis");
        let ttl: i64 = conn.ttl(session_key(&channel_id)).await.expect("ttl");
        assert!(
            ttl > 0 && ttl <= WATCH_SESSION_TTL_SECS as i64,
            "create must arm the session TTL, got {ttl}"
        );
        let seq_ttl: i64 = conn.ttl(seq_key(&channel_id)).await.expect("seq ttl");
        assert!(
            seq_ttl > 0 && seq_ttl <= WATCH_SESSION_TTL_SECS as i64,
            "the seq counter must not be immortal, got {seq_ttl}"
        );

        // Every write re-arms: shrink the TTL, write, and it is full again.
        let _: () = conn
            .expire(session_key(&channel_id), 5)
            .await
            .expect("shrink");
        let updated = update_watch_session(&channel_id, |s| s.playing = true)
            .await
            .expect("update")
            .expect("session still there");
        assert!(updated.seq > created.seq);
        let ttl: i64 = conn.ttl(session_key(&channel_id)).await.expect("ttl");
        assert!(ttl > 5, "a write must refresh the TTL, got {ttl}");

        // Lapse both keys: the session is gone with no event (passive GC) …
        let _: () = conn
            .pexpire(session_key(&channel_id), 1)
            .await
            .expect("lapse session");
        let _: () = conn
            .pexpire(seq_key(&channel_id), 1)
            .await
            .expect("lapse seq");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            fetch_watch_session(&channel_id)
                .await
                .expect("fetch")
                .is_none(),
            "an expired session must read as absent"
        );

        // … and the channel is NOT wedged: SET NX succeeds again.
        let recreated = create_watch_session(&channel_id, "host", media())
            .await
            .expect("re-create")
            .expect("expiry must free the channel for a fresh session");
        assert_ne!(recreated.id, created.id);

        delete_watch_session(&channel_id).await.expect("cleanup");
    }
}
