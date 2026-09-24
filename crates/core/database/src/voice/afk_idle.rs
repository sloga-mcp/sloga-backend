//! Idle claims for the AFK auto-move (AFK-channel plan, Wave 5b-2).
//!
//! A member's client reports "idle for N seconds" through
//! `PUT /channels/<id>/afk_idle`, the claim is stored here per user and
//! server, and the crond AFK sweep reads it back to decide whether to move the
//! member into the server's AFK channel. `idle_for` is CLIENT-CLAIMED, a
//! self-report from the member's own client, and grants nothing: the worst a
//! forged claim can do is move its own author into the AFK channel.
//!
//! This module is the ONLY place any of these keys is spelled. The route and
//! the sweep call the functions below and build no key string of their own
//! (Stage 2 P2-7): a sweep that retyped `joined_at:` with a typo would find
//! nobody due, forever, with every test green.
//!
//! Three keys:
//!
//! - `afk_since:{user}:{server}` = `"{channel_id}:{since_ms}"`, TTL
//!   [`AFK_SINCE_TTL_SECS`]. The client refreshes it while idle, so a client
//!   that is suspended, killed or offline stops refreshing and the claim
//!   expires: the safe direction. A lost "active again" DELETE therefore lives
//!   at most one TTL.
//! - [`AFK_IDLE_INDEX_KEY`], a ZSET of `{user}:{server}` members scored by the
//!   NEXT-ELIGIBLE epoch ms (Stage 2 P2-1), which is how the sweep finds
//!   candidates without a key-pattern SCAN. Every entry the sweep examines
//!   leaves the due range, either removed or requeued through
//!   [`requeue_score`], so a skipped entry can never sit at the front of the
//!   range and starve the ones behind it.
//! - `afk_idle_tomb:{user}:{server}`, TTL [`AFK_IDLE_TOMB_TTL_SECS`]: left by
//!   the client's withdrawal ([`withdraw_afk_since`]) so that a claim which
//!   was still in flight when the member came back cannot land after the
//!   withdrawal and stand with nobody left to take it back (5b-2.1 re-audit
//!   R-1). While it stands, [`set_afk_since`] writes nothing.
//!
//! The claim is deliberately NOT part of the voice-state teardown script. It
//! outlives a leave by at most its TTL, `create_voice_state` deletes it on
//! every join (so a stale claim cannot resurrect in the next call, Stage 1
//! I-2), and the sweep checks it against the live pointer and `joined_at:`
//! before acting on it.

use iso8601_timestamp::Timestamp;
use redis_kiss::{
    redis::{cmd, Cmd, ExistenceCheck, Pipeline, SetExpiry, SetOptions},
    AsyncCommands,
};
use revolt_result::{create_error, Result, ToRevoltError};

use super::get_connection;

/// Lifetime of an idle claim. The client refreshes about every 60 s while idle
/// (on its 5 s tick, plus request latency), so ONE missed refresh is reliably
/// survived. Two in a row put the next refresh at about 180 s, racing the
/// expiry, and the claim may lapse. A lapse only delays the move: the next
/// refresh re-creates the claim from the client's `idle_for`.
pub const AFK_SINCE_TTL_SECS: u64 = 180;

/// The candidate index the sweep reads (see the module docs).
pub const AFK_IDLE_INDEX_KEY: &str = "afk_idle";

/// The longest idle period a claim may assert, in seconds: the longest AFK
/// timeout a server can choose (`AFK_TIMEOUT_CHOICES`). A longer claim could
/// not make anyone due any sooner.
const MAX_IDLE_FOR_SECS: u32 = 3600;

/// How long after `since` a new claim is first looked at. Nobody can be due
/// sooner: the shortest AFK timeout is 60 s.
const INDEX_FIRST_LOOK_MS: i64 = 60_000;

/// Requeue delay after a "not yet" (capped), a skip, or a bad config.
const REQUEUE_NEXT_LOOK_MS: i64 = 60_000;

/// Requeue delay after the move was refused on policy grounds.
const REQUEUE_REFUSED_MS: i64 = 300_000;

/// Requeue delay after an infrastructure failure or a timed-out move.
const REQUEUE_INFRA_MS: i64 = 30_000;

/// Lifetime of the withdrawal tombstone (5b-2.1 re-audit R-1).
///
/// The race it closes: a client gives up on a claim PUT (its request timed
/// out, or the response was lost) and sends the withdrawal DELETE, but Rocket
/// keeps running a handler after its client has gone, so the stalled PUT can
/// still land AFTER the DELETE. It then finds no claim, creates one with a
/// due `since`, and the client, which believes it has nothing posted, never
/// withdraws it: the sweep moves a member who is active.
///
/// Why 60 s: it is the shortest AFK timeout a server can choose
/// (`Server::AFK_TIMEOUT_CHOICES`), and every withdrawal the client sends
/// comes with a reset of its idle clock (activity, a tick gap, or the watch
/// being disarmed all set its last-activity time to now). So the client
/// cannot SEND a legitimate claim sooner than 60 s after the activity that
/// caused the withdrawal. That is measured from the activity, not from the
/// moment the DELETE lands: a DELETE that spends time in flight or in its
/// retries plants a tomb that still stands for a full 60 s after it lands,
/// and a legitimate claim can arrive inside that span. Such a claim (and any
/// other legitimate claim that meets a standing tomb) is refused, and the
/// outcome is only a delay: the client's next refresh re-creates it with the
/// true `since`, which is computed from `idle_for`.
///
/// Residual: a PUT stalled for longer than this after the DELETE still lands.
pub const AFK_IDLE_TOMB_TTL_SECS: u64 = 60;

/// `afk_since:{user}:{server}` — the only builder of this key.
pub fn afk_since_key(user_id: &str, server_id: &str) -> String {
    format!("afk_since:{user_id}:{server_id}")
}

/// `afk_idle_tomb:{user}:{server}` — the only builder of this key.
pub fn afk_idle_tomb_key(user_id: &str, server_id: &str) -> String {
    format!("afk_idle_tomb:{user_id}:{server_id}")
}

/// Whether a claim write must be skipped: a withdrawal tombstone stands, so
/// this PUT may be a stale one landing after its own withdrawal. Pure, and
/// kept separate from [`afk_since_write`] (which decides HOW to write) so each
/// rule is pinned on its own.
pub fn afk_since_blocked(tomb: bool) -> bool {
    tomb
}

/// How far a claim's `idle_for` may run past the member's time in the call
/// (`now − joined_at`) before [`afk_since_predates_join`] refuses it, in ms.
///
/// What it has to absorb, for a claim that IS legitimate:
///
/// - Where `joined_at:` comes from. voice-ingress writes it in
///   `create_voice_state` on the SFU's `participant_joined` webhook, and the
///   VALUE is that event's `created_at`: stamped by the SFU when the
///   participant joined, in WHOLE seconds, truncated. When the webhook is
///   delivered does not enter into it (until it is delivered there is no
///   `joined_at:` and the check does not apply), and the truncation puts
///   `joined_at` up to 1 s EARLY, which only shrinks the excess.
/// - Where the client's idle clock starts. `#startIdleWatch` sets
///   `lastActivityAt` to now in the Room's `connected` listener
///   (`state.tsx`), and `idlePolicy.ts` holds the clock at now while not
///   connected. The Room and the SFU observe the same join handshake, so the
///   client's clock starts on the order of a network round trip away from
///   the SFU's stamp, in either direction. (Reasoned from the two code
///   paths, not measured on a live leg.)
/// - `idle_for` is rounded down to whole seconds by the client, and the
///   request's own latency is added to `now`; both only shrink the excess.
/// - Clock skew between the SFU node, which stamps `joined_at`, and this
///   server, which reads `now`. An SFU clock running AHEAD grows the excess
///   one for one. NTP keeps that to milliseconds; the slack leaves room for
///   several seconds of it.
///
/// So a legitimate claim's excess is about a round trip plus the skew:
/// under a second on synchronized hosts. 10 s covers that many times over.
///
/// Why not larger: the claim this exists to refuse (F-A2) is a stale refresh
/// from a dropped connection that lands just after the same-channel rejoin.
/// Its `idle_for` is at least the shortest timeout (60 s: the client claims
/// only at the timeout), while `now − joined_at` is seconds, so it is refused
/// for as long as it lands within `60 s − slack` of the rejoin — 50 s here,
/// far longer than any request stays in flight.
///
/// 🔴 The excess of a connection is CONSTANT across its refreshes (both
/// sides advance with the wall clock), so a slack smaller than the real gap
/// would refuse every claim from that connection until its user is next
/// active. That direction is safe (nobody is moved) but silent.
///
/// Known case of exactly that: a full SDK reconnect (a new SFU participant,
/// so a new `participant_joined` and a new `joined_at`) that completes
/// between two of the client's 5 s idle ticks. No tick sees the Room
/// disconnected, so the idle clock is not restarted, and the connection's
/// excess is the idle time it had before the reconnect: its claims are
/// refused until the user is next active. The cure is client-side (restart
/// the idle clock on the Room's reconnect events), not a larger slack.
const AFK_CLAIM_JOIN_SLACK_MS: i64 = 10_000;

/// Whether a claim says the member has been idle for longer than they have
/// been in the call (AFK Stage 6 F-A2): `idle_for` exceeds `now − joined_at`
/// by more than [`AFK_CLAIM_JOIN_SLACK_MS`]. Such a claim was measured on an
/// earlier connection, typically a stale refresh from a dropped one that lands
/// after the rejoin's `create_voice_state`, and it writes nothing: the clamp
/// in [`afk_since_ms`] would otherwise turn it into `since = joined_at`, and
/// an active member would be moved one timeout after the rejoin with no
/// claim of their own to withdraw.
///
/// No `joined_at:` (not written yet, or unreadable) refuses nothing, which is
/// the behavior before this check. The raw `idle_for` is compared, not the
/// capped one: the cap bounds how far back `since` may go, and must not make
/// an impossible claim look possible. Pure, and pinned by value.
pub fn afk_since_predates_join(now_ms: i64, idle_for: u32, joined_at_ms: Option<i64>) -> bool {
    let Some(joined_at_ms) = joined_at_ms else {
        return false;
    };

    i64::from(idle_for) * 1000 > now_ms - joined_at_ms + AFK_CLAIM_JOIN_SLACK_MS
}

/// A parsed idle claim: the channel the member was idle in, and since when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfkIdleClaim {
    pub channel_id: String,
    /// Epoch milliseconds, server-stamped (see [`afk_since_ms`]).
    pub since_ms: i64,
}

impl AfkIdleClaim {
    /// The stored value, `{channel_id}:{since_ms}`; [`parse_afk_since`] is its
    /// inverse. Channel ids are ULIDs and contain no `:`.
    pub fn to_value(&self) -> String {
        format!("{}:{}", self.channel_id, self.since_ms)
    }
}

/// Parse a stored claim. `None` for anything [`AfkIdleClaim::to_value`] could
/// not have written: an empty channel, or a `since` that is not one integer.
pub fn parse_afk_since(value: &str) -> Option<AfkIdleClaim> {
    let (channel_id, since_ms) = value.split_once(':')?;
    if channel_id.is_empty() {
        return None;
    }

    Some(AfkIdleClaim {
        channel_id: channel_id.to_string(),
        since_ms: since_ms.parse().ok()?,
    })
}

/// How a PUT writes the claim (Stage 2 P2-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfkSinceWrite {
    /// No claim: `SET … NX EX`.
    Create,
    /// A claim for the same channel: `EXPIRE` only. A refresh never moves
    /// `since`, which is what makes a heartbeat safe to repeat.
    Refresh,
    /// A claim naming a DIFFERENT channel: `SET … XX EX` with a fresh
    /// `since`. Refreshing it instead would prolong a claim for the wrong
    /// channel (a PUT for A racing the join to B).
    Replace,
}

/// Decide the write for a claim against what is stored. GET, then decide,
/// then write: the race between the GET and the write is benign, because the
/// sweep clears any claim whose channel does not match the live pointer.
pub fn afk_since_write(existing: Option<&AfkIdleClaim>, target_channel: &str) -> AfkSinceWrite {
    match existing {
        None => AfkSinceWrite::Create,
        Some(claim) if claim.channel_id == target_channel => AfkSinceWrite::Refresh,
        Some(_) => AfkSinceWrite::Replace,
    }
}

/// When the member went idle, in epoch ms, from the client's relative
/// `idle_for` (seconds) and the server's clock: no client wall-clock is ever
/// trusted.
///
/// `idle_for` is capped at [`MAX_IDLE_FOR_SECS`], and the result is clamped to
/// the member's `joined_at:` when there is one: nobody has been idle in a call
/// since before they joined it. That clamp is also what makes the sweep's
/// `since >= joined_at` staleness test hold for every claim written after the
/// join.
pub fn afk_since_ms(now_ms: i64, idle_for: u32, joined_at_ms: Option<i64>) -> i64 {
    let since_ms = now_ms - i64::from(idle_for.min(MAX_IDLE_FOR_SECS)) * 1000;

    match joined_at_ms {
        Some(joined_at_ms) => since_ms.max(joined_at_ms),
        None => since_ms,
    }
}

/// `{user}:{server}` — a member of [`AFK_IDLE_INDEX_KEY`].
pub fn afk_idle_member(user_id: &str, server_id: &str) -> String {
    format!("{user_id}:{server_id}")
}

/// The `(user, server)` of an index member: exactly two non-empty parts.
pub fn parse_afk_idle_member(member: &str) -> Option<(&str, &str)> {
    let mut parts = member.split(':');
    let (user_id, server_id) = (parts.next()?, parts.next()?);

    if parts.next().is_some() || user_id.is_empty() || server_id.is_empty() {
        return None;
    }

    Some((user_id, server_id))
}

/// Every key the sweep reads for one member, in this order: the claim, the
/// per-server pointer `{user}:{server}`, `joined_at:`, `screensharing:`,
/// `camera:`, `recording:`. The last five are `create_voice_state`'s keys for
/// a server channel, spelled the same way (pinned against it by test).
pub fn idle_state_keys(user_id: &str, server_id: &str) -> [String; 6] {
    let unique_key = format!("{user_id}:{server_id}");

    [
        afk_since_key(user_id, server_id),
        unique_key.clone(),
        format!("joined_at:{unique_key}"),
        format!("screensharing:{unique_key}"),
        format!("camera:{unique_key}"),
        format!("recording:{unique_key}"),
    ]
}

/// One member's idle state, as one MGET over [`idle_state_keys`] read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdleState {
    /// `None` when the key is gone or unreadable.
    pub claim: Option<AfkIdleClaim>,
    /// The channel the per-server pointer names, if any.
    pub pointer: Option<String>,
    /// `None` when absent or not an integer.
    pub joined_at_ms: Option<i64>,
    pub screensharing: bool,
    pub camera: bool,
    pub recording: bool,
}

/// Whether a voice flag reads as set. The flags are written by
/// `.set(key, bool)`, which the redis-rs fork (`523b293`, `types.rs:955-961`)
/// encodes as `"1"` / `"0"`; its own bool decoding (`types.rs:1281-1308`)
/// reads nil as false. Anything else is not a value the writers produce, and
/// is read as SET: every one of these flags only ever stops a move, so an
/// unreadable one errs toward leaving the member where they are.
fn voice_flag_is_set(value: Option<&str>) -> bool {
    matches!(value, Some(value) if value != "0")
}

/// Decode the MGET of [`idle_state_keys`], in that order.
fn idle_state_from_values(values: [Option<String>; 6]) -> IdleState {
    let [claim, pointer, joined_at, screensharing, camera, recording] = values;

    IdleState {
        claim: claim.as_deref().and_then(parse_afk_since),
        pointer,
        joined_at_ms: joined_at.and_then(|value| value.parse().ok()),
        screensharing: voice_flag_is_set(screensharing.as_deref()),
        camera: voice_flag_is_set(camera.as_deref()),
        recording: voice_flag_is_set(recording.as_deref()),
    }
}

/// What the sweep does with an index entry it examined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfkRequeue {
    /// Idle, but the timeout has not elapsed yet.
    NotYet,
    /// Skipped this time: streaming, camera, recording, or the server's AFK
    /// config is not usable.
    Skip,
    /// The move was refused on policy grounds (permissions, caps, ...).
    Refused,
    /// Redis, the SFU, or the move itself failed or timed out.
    InfraError,
    /// Nothing left to do: remove the entry.
    Drop,
}

/// The score an examined index entry is requeued at, or `None` to remove it.
///
/// - `NotYet` ⇒ the deadline `since + timeout`, but no later than one minute
///   from now, so a timeout change is noticed within a minute;
/// - `Skip` ⇒ now + 60 s; `Refused` ⇒ now + 300 s; `InfraError` ⇒ now + 30 s;
/// - `Drop` ⇒ `None`.
///
/// Every score is strictly after `now_ms`, so the entry leaves the range the
/// sweep just read (`-inf ..= now`). For `NotYet` that already follows from
/// what "not yet" means (`since + timeout > now`); the `now_ms + 1` floor is
/// there for a caller that says `NotYet` about an entry whose deadline has in
/// fact passed, which would otherwise stay at the front of the range and be
/// read first on every tick.
pub fn requeue_score(r: AfkRequeue, since_ms: i64, timeout_secs: u32, now_ms: i64) -> Option<i64> {
    match r {
        AfkRequeue::NotYet => Some(
            (since_ms + i64::from(timeout_secs) * 1000)
                .min(now_ms + REQUEUE_NEXT_LOOK_MS)
                .max(now_ms + 1),
        ),
        AfkRequeue::Skip => Some(now_ms + REQUEUE_NEXT_LOOK_MS),
        AfkRequeue::Refused => Some(now_ms + REQUEUE_REFUSED_MS),
        AfkRequeue::InfraError => Some(now_ms + REQUEUE_INFRA_MS),
        AfkRequeue::Drop => None,
    }
}

fn now_ms() -> i64 {
    Timestamp::now_utc()
        .duration_since(Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

/// The Redis command for one [`AfkSinceWrite`]. Pure, so each arm's exact
/// command is pinned by value.
fn afk_since_write_cmd(write: AfkSinceWrite, key: &str, claim: &AfkIdleClaim) -> Cmd {
    let ttl = SetExpiry::EX(AFK_SINCE_TTL_SECS as usize);
    let mut command;

    match write {
        AfkSinceWrite::Create => {
            command = cmd("SET");
            command.arg(key).arg(claim.to_value()).arg(
                SetOptions::default()
                    .conditional_set(ExistenceCheck::NX)
                    .with_expiration(ttl),
            );
        }
        AfkSinceWrite::Refresh => {
            command = cmd("EXPIRE");
            command.arg(key).arg(AFK_SINCE_TTL_SECS);
        }
        AfkSinceWrite::Replace => {
            command = cmd("SET");
            command.arg(key).arg(claim.to_value()).arg(
                SetOptions::default()
                    .conditional_set(ExistenceCheck::XX)
                    .with_expiration(ttl),
            );
        }
    }

    command
}

/// `ZADD afk_idle NX <score> <member>`: restores a lost index entry and never
/// moves an existing one. Raw, because the fork has no ZADD-with-flags helper
/// (`commands/mod.rs:548` is a plain ZADD).
fn afk_idle_add_cmd(member: &str, score: i64) -> Cmd {
    let mut command = cmd("ZADD");
    command
        .arg(AFK_IDLE_INDEX_KEY)
        .arg("NX")
        .arg(score)
        .arg(member);
    command
}

/// `ZADD afk_idle XX <score> <member>`: moves an existing entry and never
/// re-creates one the sweep or a clear has just removed.
fn afk_idle_requeue_cmd(member: &str, score: i64) -> Cmd {
    let mut command = cmd("ZADD");
    command
        .arg(AFK_IDLE_INDEX_KEY)
        .arg("XX")
        .arg(score)
        .arg(member);
    command
}

/// `ZRANGEBYSCORE afk_idle -inf <now_ms> LIMIT 0 <limit>`: the entries due by
/// now, earliest first. The upper bound IS `now_ms`: a larger bound hands the
/// sweep entries that are not due yet, every one of which it would then read
/// and requeue for nothing.
fn afk_idle_due_cmd(now_ms: i64, limit: usize) -> Cmd {
    let mut command = cmd("ZRANGEBYSCORE");
    command
        .arg(AFK_IDLE_INDEX_KEY)
        .arg("-inf")
        .arg(now_ms)
        .arg("LIMIT")
        .arg(0)
        .arg(limit);
    command
}

/// `MGET` over [`idle_state_keys`] for (`user_id`, `server_id`), in that order.
fn idle_state_read_cmd(user_id: &str, server_id: &str) -> Cmd {
    let keys = idle_state_keys(user_id, server_id);
    let mut command = cmd("MGET");
    command.arg(&keys[..]);
    command
}

/// `DEL` the claim and `ZREM` its index entry, in one round trip.
fn afk_since_clear_pipeline(user_id: &str, server_id: &str) -> Pipeline {
    let mut pipeline = Pipeline::new();
    pipeline
        .del(afk_since_key(user_id, server_id))
        .zrem(AFK_IDLE_INDEX_KEY, afk_idle_member(user_id, server_id));
    pipeline
}

/// `EXISTS afk_idle_tomb:{user}:{server}`: whether a withdrawal tombstone
/// stands.
fn afk_idle_tomb_read_cmd(user_id: &str, server_id: &str) -> Cmd {
    let mut command = cmd("EXISTS");
    command.arg(afk_idle_tomb_key(user_id, server_id));
    command
}

/// The client's withdrawal, in one round trip: `SET` the tombstone with its
/// TTL, then `DEL` the claim and `ZREM` its index entry.
///
/// The tombstone goes FIRST. The pipeline is not a transaction, so a PUT on
/// another connection could read between its commands; with the tomb first,
/// a PUT that reads after the claim is gone also finds the tomb. With it last,
/// such a PUT would find neither and re-create the claim.
fn afk_since_withdraw_pipeline(user_id: &str, server_id: &str) -> Pipeline {
    let mut pipeline = Pipeline::new();
    pipeline
        .set_options(
            afk_idle_tomb_key(user_id, server_id),
            1,
            SetOptions::default().with_expiration(SetExpiry::EX(AFK_IDLE_TOMB_TTL_SECS as usize)),
        )
        .del(afk_since_key(user_id, server_id))
        .zrem(AFK_IDLE_INDEX_KEY, afk_idle_member(user_id, server_id));
    pipeline
}

/// Record (or refresh) an idle claim. The caller has already checked that the
/// member is in `channel_id` and that the server has an AFK channel and
/// timeout; this only writes.
///
/// Nothing at all is written while a withdrawal tombstone stands (see
/// [`AFK_IDLE_TOMB_TTL_SECS`]): no SET, no EXPIRE, no ZADD, and the call still
/// succeeds. The tomb is read before anything else, and read AGAIN after the
/// writes (N-1): a withdrawal whose tomb landed between the first read and
/// the writes is found there, and the claim and its index entry just written
/// are deleted. The withdrawal sets its tomb BEFORE it deletes, so a
/// withdrawal the second read does not see has not deleted yet, and its own
/// DEL and ZREM land after these writes.
///
/// Nothing is written either for a claim whose `idle_for` is longer than the
/// member has been in the call (see [`afk_since_predates_join`]).
///
/// `since` is stamped here, from `idle_for` and this server's clock, and
/// clamped to `joined_at:`. A same-channel claim is only re-expired, so its
/// `since` never moves; a claim for another channel is replaced; a value that
/// does not parse is replaced too, rather than left to block every write
/// until it expires. The index entry is then re-added with NX, which restores
/// one that was lost without ever moving one that exists.
pub async fn set_afk_since(
    user_id: &str,
    server_id: &str,
    channel_id: &str,
    idle_for: u32,
) -> Result<()> {
    let [key, _pointer, joined_at_key, ..] = idle_state_keys(user_id, server_id);
    let mut conn = get_connection().await?;

    // Possibly a stale PUT landing after its own withdrawal: write nothing.
    let tomb: bool = afk_idle_tomb_read_cmd(user_id, server_id)
        .query_async(&mut *conn)
        .await
        .to_internal_error()?;
    if afk_since_blocked(tomb) {
        return Ok(());
    }

    let (existing, joined_at): (Option<String>, Option<String>) = conn
        .mget(&[key.as_str(), joined_at_key.as_str()])
        .await
        .to_internal_error()?;
    let joined_at_ms = joined_at.and_then(|value| value.parse::<i64>().ok());
    let existing_claim = existing.as_deref().and_then(parse_afk_since);

    // One clock reading for both the refusal below and the stamp.
    let now = now_ms();

    // Idle for longer than they have been in the call: measured on an
    // earlier connection (F-A2). Write nothing.
    if afk_since_predates_join(now, idle_for, joined_at_ms) {
        return Ok(());
    }

    let write = if existing.is_some() && existing_claim.is_none() {
        AfkSinceWrite::Replace
    } else {
        afk_since_write(existing_claim.as_ref(), channel_id)
    };
    let fresh = AfkIdleClaim {
        channel_id: channel_id.to_string(),
        since_ms: afk_since_ms(now, idle_for, joined_at_ms),
    };
    // The `since` that stands after this write: a refresh keeps the old one.
    let since_ms = match (write, &existing_claim) {
        (AfkSinceWrite::Refresh, Some(existing)) => existing.since_ms,
        _ => fresh.since_ms,
    };

    afk_since_write_cmd(write, &key, &fresh)
        .query_async::<_, ()>(&mut *conn)
        .await
        .to_internal_error()?;
    afk_idle_add_cmd(
        &afk_idle_member(user_id, server_id),
        since_ms + INDEX_FIRST_LOOK_MS,
    )
    .query_async::<_, ()>(&mut *conn)
    .await
    .to_internal_error()?;

    // N-1: the tomb again, now that the claim is written. If a withdrawal
    // planted one since the first read, take back what was just written.
    let tomb_after_write: bool = afk_idle_tomb_read_cmd(user_id, server_id)
        .query_async(&mut *conn)
        .await
        .to_internal_error()?;
    if afk_since_blocked(tomb_after_write) {
        afk_since_clear_pipeline(user_id, server_id)
            .query_async::<_, ()>(&mut *conn)
            .await
            .to_internal_error()?;
    }

    Ok(())
}

/// The stored claim, if any (an unreadable value reads as none).
pub async fn get_afk_since(user_id: &str, server_id: &str) -> Result<Option<AfkIdleClaim>> {
    let value: Option<String> = get_connection()
        .await?
        .get(afk_since_key(user_id, server_id))
        .await
        .to_internal_error()?;

    Ok(value.as_deref().and_then(parse_afk_since))
}

/// Forget a claim: the key and its index entry, in one round trip.
///
/// Leaves NO tombstone. The sweep clears through here, and so does a claim
/// PUT made from inside the AFK channel; neither is a client withdrawal, and
/// neither may block the member's next claim. The client's own withdrawal
/// uses [`withdraw_afk_since`].
pub async fn clear_afk_since(user_id: &str, server_id: &str) -> Result<()> {
    let mut conn = get_connection().await?;

    afk_since_clear_pipeline(user_id, server_id)
        .query_async::<_, ()>(&mut *conn)
        .await
        .to_internal_error()
}

/// The client's withdrawal of its claim (the DELETE route): clears the claim
/// and its index entry exactly as [`clear_afk_since`] does, and leaves a
/// tombstone for [`AFK_IDLE_TOMB_TTL_SECS`] under which [`set_afk_since`]
/// writes nothing, so a claim PUT still in flight cannot re-create it.
pub async fn withdraw_afk_since(user_id: &str, server_id: &str) -> Result<()> {
    let mut conn = get_connection().await?;

    afk_since_withdraw_pipeline(user_id, server_id)
        .query_async::<_, ()>(&mut *conn)
        .await
        .to_internal_error()
}

/// Everything the sweep needs about one member, in one MGET.
pub async fn read_idle_state(user_id: &str, server_id: &str) -> Result<IdleState> {
    let mut conn = get_connection().await?;

    let values: Vec<Option<String>> = idle_state_read_cmd(user_id, server_id)
        .query_async(&mut *conn)
        .await
        .to_internal_error()?;
    let values: [Option<String>; 6] = values
        .try_into()
        .map_err(|_| create_error!(InternalError))?;

    Ok(idle_state_from_values(values))
}

/// Index members whose next-eligible time has come: `ZRANGEBYSCORE afk_idle
/// -inf <now_ms> LIMIT 0 <limit>`, earliest first.
pub async fn due_idle_members(now_ms: i64, limit: usize) -> Result<Vec<String>> {
    let mut conn = get_connection().await?;

    afk_idle_due_cmd(now_ms, limit)
        .query_async(&mut *conn)
        .await
        .to_internal_error()
}

/// Move an index entry to `score` (from [`requeue_score`]). XX: an entry that
/// was removed in the meantime stays removed.
pub async fn requeue_idle_member(member: &str, score: i64) -> Result<()> {
    let mut conn = get_connection().await?;

    afk_idle_requeue_cmd(member, score)
        .query_async::<_, ()>(&mut *conn)
        .await
        .to_internal_error()
}

/// Remove an index entry, leaving any claim key to its TTL.
pub async fn drop_idle_member(member: &str) -> Result<()> {
    get_connection()
        .await?
        .zrem(AFK_IDLE_INDEX_KEY, member)
        .await
        .to_internal_error()
}

#[cfg(test)]
mod tests {
    use super::*;
    use redis_kiss::redis::ToRedisArgs;

    /// The exact bytes a command sends, for comparing a built command with
    /// one written out by hand.
    fn packed(command: &Cmd) -> String {
        String::from_utf8_lossy(&command.get_packed_command()).into_owned()
    }

    #[test]
    fn afk_since_key_is_spelled_exactly() {
        assert_eq!(afk_since_key("USER", "SRV"), "afk_since:USER:SRV");
    }

    #[test]
    fn afk_since_ttl_is_three_minutes() {
        assert_eq!(AFK_SINCE_TTL_SECS, 180);
    }

    /// This file's shipping text, test module excluded, as function bodies
    /// with comment lines dropped and whitespace collapsed.
    fn shipping_fn_body(definition: &str) -> String {
        const SOURCE: &str = include_str!("afk_idle.rs");
        let shipping = &SOURCE[..SOURCE
            .find("#[cfg(test)]\nmod tests")
            .expect("afk_idle.rs has a test module")];
        let at = shipping
            .find(definition)
            .unwrap_or_else(|| panic!("afk_idle.rs no longer defines `{definition}`"));
        let open = at + shipping[at..].find('\u{7b}').expect("a body");
        let mut depth = 0i64;
        let mut close = None;
        for (i, ch) in shipping[open..].char_indices() {
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
        shipping[open + 1..close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// R-1 (5b-2.1 re-audit): the tombstone lives 60 s, which is the shortest
    /// AFK timeout a server can choose. Longer would delay legitimate claims
    /// for nothing; shorter would reopen the window for a stalled PUT.
    #[test]
    fn the_tomb_lives_as_long_as_the_shortest_timeout() {
        assert_eq!(AFK_IDLE_TOMB_TTL_SECS, 60);
        assert_eq!(
            AFK_IDLE_TOMB_TTL_SECS,
            u64::from(*crate::Server::AFK_TIMEOUT_CHOICES.iter().min().unwrap()),
            "the tomb must last exactly the shortest AFK timeout"
        );
    }

    #[test]
    fn afk_idle_tomb_key_is_spelled_exactly() {
        assert_eq!(afk_idle_tomb_key("USER", "SRV"), "afk_idle_tomb:USER:SRV");
    }

    /// R-1: a standing tomb blocks the claim write, and only a standing tomb.
    #[test]
    fn a_tomb_blocks_the_claim_write() {
        assert!(afk_since_blocked(true), "a tomb stands: write nothing");
        assert!(!afk_since_blocked(false), "no tomb: the claim is written");
    }

    /// R-1: the withdrawal is exactly SET tomb 1 EX 60, then DEL the claim,
    /// then ZREM its entry; the tomb read is exactly EXISTS on the tomb.
    #[test]
    fn the_withdrawal_is_the_exact_pipeline() {
        let mut expected = Pipeline::new();
        expected
            .cmd("SET")
            .arg("afk_idle_tomb:U:S")
            .arg("1")
            .arg("EX")
            .arg(60)
            .cmd("DEL")
            .arg("afk_since:U:S")
            .cmd("ZREM")
            .arg("afk_idle")
            .arg("U:S");
        assert_eq!(
            String::from_utf8_lossy(&afk_since_withdraw_pipeline("U", "S").get_packed_pipeline()),
            String::from_utf8_lossy(&expected.get_packed_pipeline()),
            "the withdrawal is SET afk_idle_tomb:U:S 1 EX 60, DEL afk_since:U:S, ZREM afk_idle U:S"
        );
        assert_eq!(
            packed(&afk_idle_tomb_read_cmd("U", "S")),
            packed(cmd("EXISTS").arg("afk_idle_tomb:U:S")),
        );
    }

    /// R-1: `set_afk_since` reads the tomb first and, when it stands, returns
    /// before its MGET and before every write command. `withdraw_afk_since`
    /// goes through the tomb pipeline; `clear_afk_since` does NOT (the sweep
    /// and the AFK-channel PUT clear through it and must not block the next
    /// claim). Mutations: the early return deleted or moved below a write,
    /// the check inverted, the withdrawal routed through the plain clear, or
    /// the clear routed through the withdrawal.
    #[test]
    fn a_claim_write_stops_at_a_tomb_and_only_the_withdrawal_leaves_one() {
        let set = shipping_fn_body("pub async fn set_afk_since(");
        let at = |needle: &str| {
            set.find(needle)
                .unwrap_or_else(|| panic!("`set_afk_since` lost `{needle}`: {set}"))
        };

        const READ: &str = "let tomb: bool = afk_idle_tomb_read_cmd(user_id, server_id)";
        const STOP: &str = "if afk_since_blocked(tomb) \u{7b} return Ok(()); \u{7d}";
        assert_eq!(set.matches(STOP).count(), 1, "exactly one tomb stop: {set}");
        let stop = at(STOP);
        assert!(at(READ) < stop, "the tomb is read before it is checked");
        for later in [
            ".mget(",
            "afk_since_write_cmd(",
            "afk_idle_add_cmd(",
            ".query_async::<_, ()>(",
        ] {
            assert!(
                stop < at(later),
                "the tomb stop must precede `{later}`: {set}"
            );
        }

        let withdraw = shipping_fn_body("pub async fn withdraw_afk_since(");
        assert!(
            withdraw.contains("afk_since_withdraw_pipeline(user_id, server_id)"),
            "the withdrawal must leave a tomb: {withdraw}"
        );

        let clear = shipping_fn_body("pub async fn clear_afk_since(");
        assert!(
            clear.contains("afk_since_clear_pipeline(user_id, server_id)")
                && !clear.contains("tomb")
                && !clear.contains("withdraw"),
            "the plain clear must leave no tomb: {clear}"
        );
    }

    /// N-1 (Stage 6): after the claim write and the index ZADD,
    /// `set_afk_since` reads the tomb a SECOND time and, when it stands,
    /// deletes the claim and its index entry through the same clear pipeline
    /// the sweep uses (DEL + ZREM, pinned by value in
    /// `the_member_read_and_clear_address_user_then_server`). Mutations: the
    /// re-check deleted, moved above either write, its condition inverted, or
    /// its clear swapped for anything else.
    #[test]
    fn a_tomb_planted_during_the_write_takes_the_claim_back() {
        let set = shipping_fn_body("pub async fn set_afk_since(");
        let at = |needle: &str| {
            set.find(needle)
                .unwrap_or_else(|| panic!("`set_afk_since` lost `{needle}`: {set}"))
        };

        const READ: &str = "afk_idle_tomb_read_cmd(user_id, server_id)";
        assert_eq!(
            set.matches(READ).count(),
            2,
            "the tomb is read exactly twice, before and after the writes: {set}"
        );
        let recheck = set.rfind(READ).expect("counted above");
        for write in ["afk_since_write_cmd(", "afk_idle_add_cmd("] {
            assert!(
                at(write) < recheck,
                "the second tomb read must follow `{write}`: {set}"
            );
        }

        const TAKE_BACK: &str = "let tomb_after_write: bool = afk_idle_tomb_read_cmd(user_id, \
             server_id) .query_async(&mut *conn) .await .to_internal_error()?; \
             if afk_since_blocked(tomb_after_write) \u{7b} \
             afk_since_clear_pipeline(user_id, server_id) .query_async::<_, ()>(&mut *conn) \
             .await .to_internal_error()?; \u{7d}";
        assert_eq!(
            set.matches(TAKE_BACK).count(),
            1,
            "a standing tomb after the write must clear the claim and its entry: {set}"
        );
        assert!(at(TAKE_BACK) > at("afk_idle_add_cmd("));
    }

    /// F-A2 (Stage 6): a claim whose `idle_for` exceeds the member's time in
    /// the call by more than the slack is refused; one within it, or with no
    /// `joined_at` at all, is not. Mutations: `>` for `>=` (the exact-slack
    /// case), the slack dropped or grown, the check reduced to `false`, or
    /// the capped `idle_for` compared instead of the raw one.
    #[test]
    fn a_claim_idle_for_longer_than_the_call_is_refused() {
        let joined = 1_758_600_000_000_i64;

        assert_eq!(AFK_CLAIM_JOIN_SLACK_MS, 10_000);
        // A claim from a fresh rejoin is refused for as long as it can be a
        // stale refresh: its idle_for is at least the shortest timeout.
        assert!(
            AFK_CLAIM_JOIN_SLACK_MS
                < i64::from(*crate::Server::AFK_TIMEOUT_CHOICES.iter().min().unwrap()) * 1000,
            "a slack as long as the shortest timeout would let the stale claim through"
        );

        // No join time: nothing is refused, however long the claim.
        for idle_for in [0, 60, 3600, u32::MAX] {
            assert!(
                !afk_since_predates_join(joined, idle_for, None),
                "{idle_for}"
            );
        }

        // In the call for 30 s.
        let now = joined + 30_000;
        assert!(!afk_since_predates_join(now, 0, Some(joined)));
        assert!(!afk_since_predates_join(now, 30, Some(joined)));
        assert!(
            !afk_since_predates_join(now, 40, Some(joined)),
            "exactly the slack past the join is still accepted"
        );
        assert!(
            afk_since_predates_join(now, 41, Some(joined)),
            "one second past the slack is refused"
        );

        // F-A2 itself: the rejoin 2 s ago, a stale refresh carrying 120 s.
        assert!(afk_since_predates_join(joined + 2_000, 120, Some(joined)));
        // ...and the shortest timeout's claim, landing 49 s after the rejoin.
        assert!(afk_since_predates_join(joined + 49_000, 60, Some(joined)));

        // The legitimate claim: the idle clock started 1 s before the SFU's
        // stamp, and the member really has been idle the whole call.
        let now = joined + 300_000;
        assert!(!afk_since_predates_join(now, 301, Some(joined)));

        // The raw idle_for is compared, not the 3600 s cap: a call of 3700 s
        // cannot carry 5000 s of idle time.
        assert!(afk_since_predates_join(
            joined + 3_700_000,
            5000,
            Some(joined)
        ));
        assert!(!afk_since_predates_join(
            joined + 3_700_000,
            3700,
            Some(joined)
        ));
    }

    /// F-A2 (Stage 6): `set_afk_since` consults `afk_since_predates_join`
    /// after it has read `joined_at:` and before it writes anything, with the
    /// same `now` it stamps `since` from. Mutations: the stop deleted, moved
    /// below a write, or fed another clock reading.
    #[test]
    fn a_claim_that_predates_the_join_writes_nothing() {
        let set = shipping_fn_body("pub async fn set_afk_since(");
        let at = |needle: &str| {
            set.find(needle)
                .unwrap_or_else(|| panic!("`set_afk_since` lost `{needle}`: {set}"))
        };

        const STOP: &str =
            "if afk_since_predates_join(now, idle_for, joined_at_ms) \u{7b} return Ok(()); \u{7d}";
        assert_eq!(set.matches(STOP).count(), 1, "exactly one join stop: {set}");
        let stop = at(STOP);
        assert!(at("let now = now_ms();") < stop);
        assert!(
            at(".mget(") < stop,
            "the stop needs `joined_at:`, read by the MGET"
        );
        for later in [
            "afk_since_write_cmd(",
            "afk_idle_add_cmd(",
            "afk_since_ms(now, idle_for, joined_at_ms)",
        ] {
            assert!(
                stop < at(later),
                "the join stop must precede `{later}`: {set}"
            );
        }
        assert_eq!(
            set.matches("now_ms()").count(),
            1,
            "one clock reading for the stop and the stamp: {set}"
        );
    }

    #[test]
    fn a_claim_round_trips_and_nothing_else_parses() {
        let claim = AfkIdleClaim {
            channel_id: "01KX7HASD9FHBYA3XGKA5YACYX".to_string(),
            since_ms: 1_758_600_000_000,
        };
        assert_eq!(claim.to_value(), "01KX7HASD9FHBYA3XGKA5YACYX:1758600000000");
        assert_eq!(parse_afk_since(&claim.to_value()), Some(claim));

        for bad in ["", "C", ":1", "C:", "C:x", "C:1:2", "C: 1", "C:1.5"] {
            assert_eq!(parse_afk_since(bad), None, "{bad:?} must not parse");
        }
    }

    #[test]
    fn the_write_depends_only_on_the_stored_channel() {
        let claim = |channel: &str| AfkIdleClaim {
            channel_id: channel.to_string(),
            since_ms: 5,
        };

        assert_eq!(afk_since_write(None, "A"), AfkSinceWrite::Create);
        assert_eq!(
            afk_since_write(Some(&claim("A")), "A"),
            AfkSinceWrite::Refresh,
            "a same-channel claim is only re-expired, so `since` never moves"
        );
        assert_eq!(
            afk_since_write(Some(&claim("B")), "A"),
            AfkSinceWrite::Replace,
            "a claim naming another channel must be replaced, never refreshed"
        );
    }

    #[test]
    fn since_is_now_minus_the_capped_idle_time_clamped_to_the_join() {
        let now = 10_000_000;

        // Exact arithmetic: subtract, in milliseconds.
        assert_eq!(afk_since_ms(now, 90, None), 9_910_000);
        assert_eq!(afk_since_ms(now, 0, None), now);
        // Capped at 3600 s.
        assert_eq!(afk_since_ms(now, 3600, None), 6_400_000);
        assert_eq!(afk_since_ms(now, 4000, None), 6_400_000);
        assert_eq!(afk_since_ms(now, u32::MAX, None), 6_400_000);
        // Clamped to a later join; an earlier join changes nothing.
        assert_eq!(afk_since_ms(now, 90, Some(9_950_000)), 9_950_000);
        assert_eq!(afk_since_ms(now, 90, Some(9_000_000)), 9_910_000);
        assert_eq!(afk_since_ms(now, 4000, Some(7_000_000)), 7_000_000);
    }

    #[test]
    fn index_members_have_exactly_two_non_empty_parts() {
        assert_eq!(afk_idle_member("U", "S"), "U:S");
        assert_eq!(parse_afk_idle_member("U:S"), Some(("U", "S")));

        for bad in ["", "U", "U:", ":S", "U:S:X", "::"] {
            assert_eq!(parse_afk_idle_member(bad), None, "{bad:?} must not parse");
        }

        // A member written for (user, server) parses back to (user, server),
        // in that order, with ids of the real shape.
        let (user, server) = ("01KX7HASD9FHBYA3XGKA5YACYX", "01KX7J0000SERVER0000000000");
        assert_eq!(
            parse_afk_idle_member(&afk_idle_member(user, server)),
            Some((user, server))
        );
    }

    /// The keys by value, then against the teardown's own list for a server
    /// channel — `voice_state_teardown_input` is pinned by value against
    /// `create_voice_state`'s spelling in `mod.rs`, so a drift on either side
    /// fails here. The claim itself must NOT be among the teardown's keys:
    /// it stays out of the script (its lifetime is the TTL and the join DEL).
    #[test]
    fn idle_state_keys_are_the_voice_state_keys() {
        assert_eq!(
            idle_state_keys("U", "S"),
            [
                "afk_since:U:S",
                "U:S",
                "joined_at:U:S",
                "screensharing:U:S",
                "camera:U:S",
                "recording:U:S",
            ]
            .map(str::to_string)
        );

        let teardown = super::super::voice_state_teardown_input(
            &super::super::UserVoiceChannel {
                id: "C".to_string(),
                server_id: Some("S".to_string()),
            },
            "U",
        );
        let [claim, pointer, rest @ ..] = idle_state_keys("U", "S");
        assert_eq!(teardown.keys[0], pointer, "KEYS[1] is the pointer");
        for key in rest {
            assert!(
                teardown.keys.contains(&key),
                "{key} is not a voice-state key: {:?}",
                teardown.keys
            );
        }
        assert!(
            !teardown.keys.contains(&claim)
                && !teardown.keys.iter().any(|key| key.starts_with("afk_since")),
            "the idle claim must stay out of the teardown script: {:?}",
            teardown.keys
        );
    }

    #[test]
    fn idle_state_decodes_what_the_writers_write() {
        // The writers' encoding, from the fork itself.
        assert_eq!(true.to_redis_args(), vec![b"1".to_vec()]);
        assert_eq!(false.to_redis_args(), vec![b"0".to_vec()]);

        assert_eq!(
            idle_state_from_values(Default::default()),
            IdleState::default(),
            "nothing stored reads as nothing, with every flag clear"
        );

        let some = |value: &str| Some(value.to_string());
        assert_eq!(
            idle_state_from_values([
                some("C:5000"),
                some("C"),
                some("4000"),
                some("0"),
                some("1"),
                some("0"),
            ]),
            IdleState {
                claim: Some(AfkIdleClaim {
                    channel_id: "C".to_string(),
                    since_ms: 5000,
                }),
                pointer: some("C"),
                joined_at_ms: Some(4000),
                screensharing: false,
                camera: true,
                recording: false,
            }
        );

        // Each flag is read from its own position.
        for (position, expected) in [
            (3, (true, false, false)),
            (4, (false, true, false)),
            (5, (false, false, true)),
        ] {
            let mut values: [Option<String>; 6] = Default::default();
            values[position] = some("1");
            let state = idle_state_from_values(values);
            assert_eq!(
                (state.screensharing, state.camera, state.recording),
                expected,
                "position {position}"
            );
        }

        // Unreadable values: no claim, no join time, and a flag reads SET.
        let state = idle_state_from_values([
            some("garbage"),
            None,
            some("x"),
            some("x"),
            some("x"),
            some("x"),
        ]);
        assert_eq!(state.claim, None);
        assert_eq!(state.joined_at_ms, None);
        assert!(state.screensharing && state.camera && state.recording);
    }

    #[test]
    fn requeue_scores_every_arm() {
        let now = 1_000_000_000;

        // NotYet: the deadline, capped at a minute from now.
        assert_eq!(
            requeue_score(AfkRequeue::NotYet, now - 30_000, 60, now),
            Some(now + 30_000)
        );
        assert_eq!(
            requeue_score(AfkRequeue::NotYet, now - 10_000, 3600, now),
            Some(now + 60_000)
        );
        assert_eq!(
            requeue_score(AfkRequeue::Skip, 0, 60, now),
            Some(now + 60_000)
        );
        assert_eq!(
            requeue_score(AfkRequeue::Refused, 0, 60, now),
            Some(now + 300_000)
        );
        assert_eq!(
            requeue_score(AfkRequeue::InfraError, 0, 60, now),
            Some(now + 30_000)
        );
        assert_eq!(requeue_score(AfkRequeue::Drop, 0, 60, now), None);

        // A `NotYet` whose deadline has in fact passed still leaves the range.
        assert_eq!(
            requeue_score(AfkRequeue::NotYet, now - 120_000, 60, now),
            Some(now + 1)
        );
    }

    /// No arm ever returns a score at or before `now`: the sweep reads
    /// `-inf ..= now`, and an entry left in that range is read first on every
    /// tick.
    #[test]
    fn no_requeue_score_is_ever_due_now() {
        let now = 1_000_000_000;

        for requeue in [
            AfkRequeue::NotYet,
            AfkRequeue::Skip,
            AfkRequeue::Refused,
            AfkRequeue::InfraError,
            AfkRequeue::Drop,
        ] {
            for since in [0, now - 7_200_000, now - 60_000, now - 1, now, now + 5_000] {
                for timeout in [0, 60, 300, 900, 1800, 3600] {
                    if let Some(score) = requeue_score(requeue, since, timeout, now) {
                        assert!(
                            score > now,
                            "{requeue:?} since {since} timeout {timeout}: {score} <= {now}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn each_claim_write_is_the_exact_command() {
        let claim = AfkIdleClaim {
            channel_id: "C".to_string(),
            since_ms: 1000,
        };

        assert_eq!(
            packed(&afk_since_write_cmd(
                AfkSinceWrite::Create,
                "afk_since:U:S",
                &claim
            )),
            packed(
                cmd("SET")
                    .arg("afk_since:U:S")
                    .arg("C:1000")
                    .arg("NX")
                    .arg("EX")
                    .arg(180)
            ),
            "a new claim is SET NX EX 180"
        );
        assert_eq!(
            packed(&afk_since_write_cmd(
                AfkSinceWrite::Refresh,
                "afk_since:U:S",
                &claim
            )),
            packed(cmd("EXPIRE").arg("afk_since:U:S").arg(180)),
            "a refresh only re-expires"
        );
        assert_eq!(
            packed(&afk_since_write_cmd(
                AfkSinceWrite::Replace,
                "afk_since:U:S",
                &claim
            )),
            packed(
                cmd("SET")
                    .arg("afk_since:U:S")
                    .arg("C:1000")
                    .arg("XX")
                    .arg("EX")
                    .arg(180)
            ),
            "a replacement is SET XX EX 180"
        );
    }

    #[test]
    fn index_writes_are_the_exact_commands() {
        assert_eq!(
            packed(&afk_idle_add_cmd("U:S", 61_000)),
            packed(cmd("ZADD").arg("afk_idle").arg("NX").arg(61_000).arg("U:S")),
            "a PUT re-adds with NX, never moving an existing score"
        );
        assert_eq!(
            packed(&afk_idle_requeue_cmd("U:S", 61_000)),
            packed(cmd("ZADD").arg("afk_idle").arg("XX").arg(61_000).arg("U:S")),
            "a requeue moves with XX, never re-creating a removed entry"
        );
    }

    /// B8 (5b-2.1 audit): the sweep's read range ends at `now`, exactly.
    #[test]
    fn the_due_read_ends_at_now() {
        assert_eq!(
            packed(&afk_idle_due_cmd(1_758_600_000_000, 500)),
            packed(
                cmd("ZRANGEBYSCORE")
                    .arg("afk_idle")
                    .arg("-inf")
                    .arg(1_758_600_000_000_i64)
                    .arg("LIMIT")
                    .arg(0)
                    .arg(500)
            ),
            "ZRANGEBYSCORE afk_idle -inf <now> LIMIT 0 <limit>"
        );
    }

    /// B8 (5b-2.1 audit): the per-member read and clear address
    /// (user, server) in that order. `U` and `S` are distinct, so a swap
    /// anywhere inside these builders names `S:U` and fails here.
    #[test]
    fn the_member_read_and_clear_address_user_then_server() {
        assert_eq!(
            packed(&idle_state_read_cmd("U", "S")),
            packed(
                cmd("MGET")
                    .arg("afk_since:U:S")
                    .arg("U:S")
                    .arg("joined_at:U:S")
                    .arg("screensharing:U:S")
                    .arg("camera:U:S")
                    .arg("recording:U:S")
            ),
            "the read is one MGET over the six keys, in order"
        );

        let mut expected = Pipeline::new();
        expected.del("afk_since:U:S").zrem("afk_idle", "U:S");
        assert_eq!(
            String::from_utf8_lossy(&afk_since_clear_pipeline("U", "S").get_packed_pipeline()),
            String::from_utf8_lossy(&expected.get_packed_pipeline()),
            "the clear is DEL afk_since:U:S then ZREM afk_idle U:S"
        );
    }
}
