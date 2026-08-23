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
//! Safety posture (review 103fdca8): destruction requires BOTH persistence
//! and re-verification. A node must look dead across TWO consecutive sweeps
//! (~5 min apart — LiveKit itself tolerates 30s of staleness, and ghosts
//! are hours old, so there is zero urgency), and every destructive step
//! re-reads the relevant state immediately before acting so a join racing
//! the sweep is never torn down. An empty `nodes` hash (LiveKit never
//! registered on this Redis) skips the sweep entirely rather than judging
//! liveness blind.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use redis_kiss::{get_connection as _get_connection, AsyncCommands, Conn};
use revolt_database::{
    events::client::EventV1,
    voice::{
        clear_voice_participant_identities, delete_channel_voice_state,
        delete_voice_participant_identity, delete_voice_state, get_channel_node,
        get_user_voice_channels, UserVoiceChannel,
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
/// forever), so minutes — not hours. Teardown needs two consecutive
/// sweeps, so effective time-to-clean is ~2x this.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// Gap between the two `nodes` reads. LiveKit heartbeats every few
/// seconds; 10s comfortably spans at least one update.
const HEARTBEAT_GAP: Duration = Duration::from_secs(10);

/// Let LiveKit register its node before the first sweep after a cold
/// start of the whole stack.
const STARTUP_DELAY: Duration = Duration::from_secs(30);

pub async fn run(db: Database, amqp: AMQP) {
    rocket::tokio::time::sleep(STARTUP_DELAY).await;

    // Nodes that looked dead LAST sweep (review MAJOR 1): a single frozen
    // 10s window can be a stats-goroutine or Redis stall — LiveKit itself
    // only distrusts a node after 30s. Only a node frozen across two
    // sweeps (5+ minutes) is treated as dead.
    let mut suspects: HashSet<String> = HashSet::new();

    loop {
        match sweep(&db, &amqp, &suspects).await {
            Ok(next_suspects) => suspects = next_suspects,
            Err(e) => {
                log::error!("voice reconciliation sweep failed: {e:?}");
                // Keep the old suspect set — a transient error must not
                // reset the two-sweep confirmation clock.
            }
        }
        rocket::tokio::time::sleep(SWEEP_INTERVAL).await;
    }
}

struct Liveness {
    /// Nodes confirmed dead (suspect last sweep AND frozen/absent now).
    dead_nodes: HashSet<String>,
    /// Nodes to suspect going into the next sweep.
    suspects: HashSet<String>,
    /// room -> node routing snapshot (for candidate discovery only; every
    /// destructive step re-reads the live entry before acting).
    room_node_map: HashMap<String, String>,
}

/// `None` when liveness cannot be judged (no registered nodes).
async fn read_liveness(prev_suspects: &HashSet<String>) -> Result<Option<Liveness>> {
    // Separate connections on purpose: holding a pooled connection across
    // the 10s gap could starve webhook handling under pool pressure.
    let first: HashMap<String, Vec<u8>> = get_connection()
        .await?
        .hgetall("nodes")
        .await
        .to_internal_error()?;
    if first.is_empty() {
        return Ok(None);
    }

    rocket::tokio::time::sleep(HEARTBEAT_GAP).await;

    let mut conn = get_connection().await?;
    let second: HashMap<String, Vec<u8>> =
        conn.hgetall("nodes").await.to_internal_error()?;

    // Frozen = present in both reads with identical bytes. A node that
    // appeared or changed between reads is live.
    let frozen: HashSet<String> = second
        .iter()
        .filter(|(id, bytes)| first.get(*id) == Some(bytes))
        .map(|(id, _)| id.clone())
        .collect();

    let room_node_map: HashMap<String, String> =
        conn.hgetall("room_node_map").await.to_internal_error()?;

    // A routing entry can also point at a node that no longer appears in
    // the `nodes` hash at all — same two-sweep rule applies.
    let absent: HashSet<String> = room_node_map
        .values()
        .filter(|node| !second.contains_key(*node))
        .cloned()
        .collect();

    let suspects: HashSet<String> = frozen.union(&absent).cloned().collect();
    let dead_nodes: HashSet<String> = suspects
        .intersection(prev_suspects)
        .cloned()
        .collect();

    Ok(Some(Liveness {
        dead_nodes,
        suspects,
        room_node_map,
    }))
}

/// Re-read a channel's routing entry and decide whether it is STILL safe
/// to treat as a ghost (review MAJOR 2): a mapping that exists and points
/// at a non-dead node means the room is live (possibly re-created since
/// the snapshot — exactly the ghost-rejoin race). `create_room` registers
/// the mapping before any client can connect, so a live call always has a
/// readable entry.
async fn still_ghost(conn: &mut Conn, channel_id: &str, dead: &HashSet<String>) -> Result<bool> {
    let node: Option<String> = conn
        .hget("room_node_map", channel_id)
        .await
        .to_internal_error()?;
    Ok(match node {
        None => true,
        Some(node) => dead.contains(&node),
    })
}

/// Names of nodes configured `remote = true`: they register on their own
/// Redis, so nothing in the local `nodes` / `room_node_map` hashes can vouch
/// for their rooms. Channels pinned to one are outside this sweep's
/// jurisdiction entirely — judging them would tear down every live call on
/// that node within two sweeps.
async fn remote_nodes() -> HashSet<String> {
    revolt_config::config()
        .await
        .api
        .livekit
        .nodes
        .iter()
        .filter(|(_, node)| node.remote)
        .map(|(name, _)| name.clone())
        .collect()
}

/// Whether the channel's Sloga-side node pin names a remote node. A missing
/// or unreadable pin is NOT treated as remote: the existing ghost rules own
/// that case, exactly as before.
async fn pinned_to_remote(channel_id: &str, remote: &HashSet<String>) -> bool {
    if remote.is_empty() {
        return false;
    }
    matches!(get_channel_node(channel_id).await, Ok(Some(node)) if remote.contains(&node))
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

async fn sweep(
    db: &Database,
    amqp: &AMQP,
    prev_suspects: &HashSet<String>,
) -> Result<HashSet<String>> {
    let Some(liveness) = read_liveness(prev_suspects).await? else {
        log::debug!("no LiveKit nodes registered; skipping reconciliation sweep");
        return Ok(HashSet::new());
    };
    let dead = &liveness.dead_nodes;
    let remote = remote_nodes().await;

    let mut conn = get_connection().await?;

    // Ghost candidates from the snapshot; each is re-verified against the
    // CURRENT routing entry immediately before teardown.
    let is_candidate = |channel_id: &str| -> bool {
        match liveness.room_node_map.get(channel_id) {
            None => true,
            Some(node) => dead.contains(node),
        }
    };

    // 1. Channels with a visible member roster whose room has no live node.
    let mut reconciled = 0usize;
    for key in scan_keys(&mut conn, "vc_members:*").await? {
        let channel_id = key.trim_start_matches("vc_members:").to_string();
        if !is_candidate(&channel_id) || pinned_to_remote(&channel_id, &remote).await {
            continue;
        }
        match still_ghost(&mut conn, &channel_id, dead).await {
            Ok(false) => continue, // re-created since the snapshot — live
            Ok(true) => match reconcile_channel(db, amqp, &mut conn, &channel_id).await {
                Ok(()) => reconciled += 1,
                Err(e) => log::error!("failed to reconcile ghost channel {channel_id}: {e:?}"),
            },
            Err(e) => log::error!("ghost re-check failed for {channel_id}: {e:?}"),
        }
    }

    // 2. Per-user membership entries pointing at dead rooms (covers state
    //    whose vc_members set is already gone). Silent — anything a client
    //    could see was announced in step 1. Per-item containment: one
    //    poisoned entry must not block the rest of the sweep forever.
    let mut user_entries = 0usize;
    let users: Vec<String> = scan_keys(&mut conn, "vc:*")
        .await?
        .into_iter()
        .map(|k| k.trim_start_matches("vc:").to_string())
        .collect();
    for user_id in &users {
        let entries = match get_user_voice_channels(user_id).await {
            Ok(entries) => entries,
            Err(e) => {
                log::error!("could not read vc:{user_id}: {e:?}");
                continue;
            }
        };
        for entry in entries {
            if !is_candidate(&entry.id) || pinned_to_remote(&entry.id, &remote).await {
                continue;
            }
            let result: Result<()> = async {
                if !still_ghost(&mut conn, &entry.id, dead).await? {
                    return Ok(());
                }
                delete_voice_state(&entry, user_id).await?;
                delete_voice_participant_identity(&entry.id, user_id).await?;
                // Step 1 clears this for rostered channels; entries seen
                // only here would otherwise leak it permanently.
                conn.del::<_, ()>(format!("node:{}", entry.id))
                    .await
                    .to_internal_error()?;
                user_entries += 1;
                Ok(())
            }
            .await;
            if let Err(e) = result {
                log::error!("failed to clear stale entry {} for {user_id}: {e:?}", entry.id);
            }
        }
    }

    // 3. Stray per-user keys with no surviving vc: entry. create_voice_state
    //    writes the vc: entry BEFORE joined_at in one pipeline, so any
    //    observed joined_at from a live join has a readable vc: entry —
    //    re-fetching the user's entries at deletion time (review MAJOR 3)
    //    fully closes the race with a join that happened mid-sweep.
    let mut strays = 0usize;
    for key in scan_keys(&mut conn, "joined_at:*").await? {
        let unique_key = key.trim_start_matches("joined_at:").to_string();
        // ULIDs contain no ':' — first segment is the user id.
        let Some((user_id, parent)) = unique_key.split_once(':') else {
            continue;
        };
        let result: Result<()> = async {
            let fresh = get_user_voice_channels(user_id).await?;
            if fresh
                .iter()
                .any(|e| e.server_id.as_deref().unwrap_or(&e.id) == parent)
            {
                return Ok(()); // a current entry claims this key set
            }
            get_connection()
                .await?
                .del::<_, ()>(&[
                    format!("joined_at:{unique_key}"),
                    format!("is_publishing:{unique_key}"),
                    format!("is_receiving:{unique_key}"),
                    format!("screensharing:{unique_key}"),
                    format!("camera:{unique_key}"),
                    format!("screen_video:{unique_key}"),
                    format!("recording:{unique_key}"),
                    unique_key.clone(),
                ])
                .await
                .to_internal_error()?;
            strays += 1;
            Ok(())
        }
        .await;
        if let Err(e) = result {
            log::error!("failed to clear stray voice keys {unique_key}: {e:?}");
        }
    }

    // 4. LiveKit's own stale routing entries. Only rooms still mapped to a
    //    CONFIRMED-dead node at deletion time — a rejoin since the snapshot
    //    rewrote the mapping to a live node and must be left alone.
    let mut livekit_ghosts = 0usize;
    for (room, snapshot_node) in liveness
        .room_node_map
        .iter()
        .filter(|(_, node)| dead.contains(*node))
    {
        let result: Result<()> = async {
            let current: Option<String> = conn
                .hget("room_node_map", room)
                .await
                .to_internal_error()?;
            if current.as_ref() != Some(snapshot_node) {
                return Ok(()); // re-created (or already gone) — not ours
            }
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
            Ok(())
        }
        .await;
        if let Err(e) = result {
            log::error!("failed to clear LiveKit routing for ghost {room}: {e:?}");
        }
    }

    if reconciled + user_entries + strays + livekit_ghosts > 0 {
        log::info!(
            "voice reconciliation: {reconciled} ghost channel(s), {user_entries} stale membership entrie(s), {strays} stray key set(s), {livekit_ghosts} LiveKit routing entrie(s) cleared"
        );
    }
    Ok(liveness.suspects)
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
    // DM (server-less) channel. A wrong shape self-heals: the mis-keyed
    // deletes no-op and steps 2-3 catch the residue via the stored entries.
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
    // sweep reclaims the group (fetch returns only OPEN groups — a close
    // that already happened makes this a no-op).
    if let Some(group) = db.fetch_open_mls_group_for_channel(channel_id).await? {
        db.close_mls_group(&group.id).await?;
    }

    log::info!(
        "reconciled ghost voice channel {channel_id} ({} member(s) released)",
        members.len()
    );
    Ok(())
}
