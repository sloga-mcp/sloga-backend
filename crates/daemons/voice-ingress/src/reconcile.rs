//! Ghost-room reconciliation sweep.
//!
//! LiveKit restarts (and any missed webhook) strand voice state in Redis
//! forever: `delete_voice_state` is event-triggered only, no voice key
//! carries a TTL, and LiveKit keeps `room_node_map` routing entries for
//! nodes that no longer exist — affected users then show as "in a call"
//! permanently (2026-07-22 audit: 33 of 34 rooms orphaned, oldest 97h).
//!
//! The sweep replays the webhooks LiveKit never delivered. Liveness truth:
//! a LiveKit node re-marshals its stats (containing `updated_at`) into the
//! `nodes` hash every few seconds, so an entry whose BYTES are unchanged
//! across a spaced double read belongs to a dead node. This is deliberately
//! byte-based — the internal `Node` proto is not part of livekit-protocol's
//! client subset, and frozen bytes survive schema changes. A room mapped to
//! a dead or unknown node is a ghost; its Sloga voice state is torn down
//! exactly like the missed `participant_left` + `room_finished` webhooks
//! would have (including client-visible `VoiceChannelLeave` events, ring
//! dismissal, and the MLS group close), and LiveKit's own stale routing
//! entries are dropped so `ListRooms`/`DeleteRoom` behave again.
//!
//! Fail-safe: an empty `nodes` hash (LiveKit never registered on this
//! Redis) skips the sweep entirely rather than judging liveness blind.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use redis_kiss::{get_connection as _get_connection, AsyncCommands, Conn};
use revolt_database::{
    events::client::EventV1,
    voice::{
        clear_voice_participant_identities, delete_channel_voice_state,
        delete_voice_participant_identity, delete_voice_state, get_user_voice_channels,
        UserVoiceChannel,
    },
    Database, AMQP,
};
use revolt_result::{create_error, Result, ToRevoltError};

async fn get_connection() -> Result<Conn> {
    _get_connection()
        .await
        .map_err(|_| create_error!(InternalError))
}

/// How often the sweep runs. Ghosts are user-visible ("X is in a call"
/// forever), so minutes — not hours.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// Gap between the two `nodes` reads. LiveKit heartbeats every few
/// seconds; 10s comfortably spans at least one update.
const HEARTBEAT_GAP: Duration = Duration::from_secs(10);

/// Let LiveKit register its node before the first sweep after a cold
/// start of the whole stack.
const STARTUP_DELAY: Duration = Duration::from_secs(30);

pub async fn run(db: Database, amqp: AMQP) {
    rocket::tokio::time::sleep(STARTUP_DELAY).await;
    loop {
        if let Err(e) = sweep(&db, &amqp).await {
            log::error!("voice reconciliation sweep failed: {e:?}");
        }
        rocket::tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

/// Room names (= channel ids) currently backed by a live LiveKit node,
/// plus the full routing map for the LiveKit-side cleanup. `None` when
/// liveness cannot be judged (no registered nodes) — callers must skip.
async fn live_rooms() -> Result<Option<(HashSet<String>, HashMap<String, String>)>> {
    let mut conn = get_connection().await?;

    let first: HashMap<String, Vec<u8>> = conn.hgetall("nodes").await.to_internal_error()?;
    if first.is_empty() {
        return Ok(None);
    }

    rocket::tokio::time::sleep(HEARTBEAT_GAP).await;

    let second: HashMap<String, Vec<u8>> = conn.hgetall("nodes").await.to_internal_error()?;

    // Dead = present in both reads with identical bytes. A node that
    // appeared between reads counts as live (conservative).
    let live_nodes: HashSet<&String> = second
        .iter()
        .filter(|(id, bytes)| first.get(*id) != Some(bytes))
        .map(|(id, _)| id)
        .collect();

    let room_node_map: HashMap<String, String> =
        conn.hgetall("room_node_map").await.to_internal_error()?;

    let live = room_node_map
        .iter()
        .filter(|(_, node)| live_nodes.contains(node))
        .map(|(room, _)| room.clone())
        .collect();

    Ok(Some((live, room_node_map)))
}

async fn scan_keys(conn: &mut Conn, pattern: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut iter = conn
        .scan_match::<_, String>(pattern)
        .await
        .to_internal_error()?;
    while let Some(key) = iter.next_item().await {
        out.push(key);
    }
    Ok(out)
}

async fn sweep(db: &Database, amqp: &AMQP) -> Result<()> {
    let Some((live, room_node_map)) = live_rooms().await? else {
        log::debug!("no LiveKit nodes registered; skipping reconciliation sweep");
        return Ok(());
    };

    let mut conn = get_connection().await?;

    // 1. Channels with a visible member roster whose room has no live node.
    let mut reconciled = 0usize;
    for key in scan_keys(&mut conn, "vc_members:*").await? {
        let channel_id = key.trim_start_matches("vc_members:").to_string();
        if live.contains(&channel_id) {
            continue;
        }
        if let Err(e) = reconcile_channel(db, amqp, &mut conn, &channel_id).await {
            log::error!("failed to reconcile ghost channel {channel_id}: {e:?}");
        } else {
            reconciled += 1;
        }
    }

    // 2. Per-user membership entries pointing at dead rooms (covers state
    //    whose vc_members set is already gone). Silent — anything a client
    //    could see was announced in step 1.
    let mut user_entries = 0usize;
    let users: Vec<String> = scan_keys(&mut conn, "vc:*")
        .await?
        .into_iter()
        .map(|k| k.trim_start_matches("vc:").to_string())
        .collect();
    for user_id in &users {
        for entry in get_user_voice_channels(user_id).await? {
            if live.contains(&entry.id) {
                continue;
            }
            delete_voice_state(&entry, user_id).await?;
            delete_voice_participant_identity(&entry.id, user_id).await?;
            user_entries += 1;
        }
    }

    // 3. Stray per-user keys with no surviving vc: entry. create_voice_state
    //    writes joined_at and the vc: entry in one pipeline, so a joined_at
    //    whose (user, parent) matches no current entry is pure debris.
    let mut valid: HashSet<(String, String)> = HashSet::new();
    for user_id in &users {
        for entry in get_user_voice_channels(user_id).await? {
            let parent = entry.server_id.clone().unwrap_or_else(|| entry.id.clone());
            valid.insert((user_id.clone(), parent));
        }
    }
    let mut strays = 0usize;
    for key in scan_keys(&mut conn, "joined_at:*").await? {
        let unique_key = key.trim_start_matches("joined_at:");
        // ULIDs contain no ':' — first segment is the user id.
        let Some((user_id, parent)) = unique_key.split_once(':') else {
            continue;
        };
        if valid.contains(&(user_id.to_string(), parent.to_string())) {
            continue;
        }
        conn.del::<_, ()>(&[
            format!("joined_at:{unique_key}"),
            format!("is_publishing:{unique_key}"),
            format!("is_receiving:{unique_key}"),
            format!("screensharing:{unique_key}"),
            format!("camera:{unique_key}"),
            unique_key.to_string(),
        ])
        .await
        .to_internal_error()?;
        strays += 1;
    }

    // 4. LiveKit's own stale routing entries. Only ever touches rooms whose
    //    node is dead — live rooms are LiveKit's business.
    let mut livekit_ghosts = 0usize;
    for (room, _) in room_node_map.iter().filter(|(r, _)| !live.contains(*r)) {
        conn.hdel::<_, _, ()>("rooms", room).await.to_internal_error()?;
        conn.hdel::<_, _, ()>("room_internal", room)
            .await
            .to_internal_error()?;
        conn.hdel::<_, _, ()>("room_node_map", room)
            .await
            .to_internal_error()?;
        conn.del::<_, ()>(&[
            format!("room_participants:{room}"),
            format!("agent_dispatch:{room}"),
        ])
        .await
        .to_internal_error()?;
        livekit_ghosts += 1;
    }

    if reconciled + user_entries + strays + livekit_ghosts > 0 {
        log::info!(
            "voice reconciliation: {reconciled} ghost channel(s), {user_entries} stale membership entrie(s), {strays} stray key set(s), {livekit_ghosts} LiveKit routing entrie(s) cleared"
        );
    }
    Ok(())
}

/// Tear one ghost channel down the way the missed webhooks would have:
/// per-member `participant_left` (state delete + VoiceChannelLeave), then
/// `room_finished` (channel-level keys, identities, ring dismissal, MLS
/// group close).
async fn reconcile_channel(
    db: &Database,
    amqp: &AMQP,
    conn: &mut Conn,
    channel_id: &str,
) -> Result<()> {
    let members: Vec<String> = conn
        .smembers(format!("vc_members:{channel_id}"))
        .await
        .to_internal_error()?;

    // The per-user keys are parented on server_id-or-channel-id; recover the
    // stored shape from a member's own vc: entry, then the DB, then assume a
    // DM (server-less) channel.
    let mut channel = None;
    for member in &members {
        if let Some(entry) = get_user_voice_channels(member)
            .await?
            .into_iter()
            .find(|c| c.id == channel_id)
        {
            channel = Some(entry);
            break;
        }
    }
    if channel.is_none() {
        if let Ok(db_channel) = db.fetch_channel(channel_id).await {
            channel = Some(UserVoiceChannel {
                id: channel_id.to_string(),
                server_id: db_channel.server().map(|s| s.to_string()),
            });
        }
    }
    let channel = channel.unwrap_or_else(|| UserVoiceChannel {
        id: channel_id.to_string(),
        server_id: None,
    });

    for user_id in &members {
        delete_voice_state(&channel, user_id).await?;
        delete_voice_participant_identity(channel_id, user_id).await?;
        EventV1::VoiceChannelLeave {
            id: channel_id.to_string(),
            user: user_id.clone(),
        }
        .p(channel_id.to_string())
        .await;
    }

    delete_channel_voice_state(&channel, &[]).await?;
    clear_voice_participant_identities(channel_id).await?;

    // Dismiss any outstanding ring notification (participant_left does this
    // when the roster empties; the initiator id only labels the push).
    if let Some(user_id) = members.first() {
        if let Err(e) = amqp
            .dm_call_updated(user_id, channel_id, None, true, None)
            .await
        {
            log::error!("failed to publish call end push for ghost {channel_id}: {e:?}");
        }
    }

    // Media E2EE: mirror room_finished so members wipe state and the crond
    // sweep reclaims the group.
    if let Some(group) = db.fetch_open_mls_group_for_channel(channel_id).await? {
        db.close_mls_group(&group.id).await?;
    }

    log::info!(
        "reconciled ghost voice channel {channel_id} ({} member(s) released)",
        members.len()
    );
    Ok(())
}
