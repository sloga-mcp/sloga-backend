//! AFK auto-move sweep (AFK-channel plan, Wave 5b-2).
//!
//! A member whose client reports them idle (`PUT /channels/<id>/afk_idle`)
//! for at least the server's `afk_timeout` is moved into the server's AFK
//! channel. The claim, its index and every idle key live in
//! `revolt_database::voice::afk_idle`; this task builds no idle key string of
//! its own (Stage 2 P2-7). The only key spelled here is its own move claim,
//! `afk_move_claim:{user}:{server}`.
//!
//! Candidates come from the `afk_idle` ZSET, scored by the next time each
//! entry is worth looking at, and never from a key-pattern SCAN (the
//! ghost-room lesson). Every entry this task examines leaves the due range:
//! it is cleared, removed, or requeued through `requeue_score` (P2-1).
//!
//! crond has no leader election. Two replicas may read the same entry; the
//! move itself is guarded by an atomic `SET NX EX` claim that is never
//! released, so it also covers the window in which a moved client is still
//! re-announcing itself from the channel it was moved out of.
//!
//! Kill switch: `features.afk_auto_move`, read at the top of every tick. The
//! config is frozen into each process at first access, so flipping it takes a
//! restart of delta (which refuses new idle claims while it is off) AND crond
//! (D-5b2-3, P2-14).

use std::{
    collections::HashMap,
    panic::AssertUnwindSafe,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use futures::FutureExt;
use redis_kiss::{
    get_connection,
    redis::{ExistenceCheck, SetExpiry, SetOptions},
    AsyncCommands,
};
use revolt_config::Features;
use revolt_database::{
    voice::{
        afk_idle::{
            clear_afk_since, drop_idle_member, due_idle_members, parse_afk_idle_member,
            read_idle_state, requeue_idle_member, requeue_score, AfkRequeue, IdleState,
        },
        move_user_to_voice_channel_expecting, VoiceClient, VoiceMoveOutcome,
    },
    Channel, Database, AMQP,
};
use revolt_result::{create_error, ErrorType, Result, ToRevoltError};
use tokio::time::{error::Elapsed, sleep};

/// Time between ticks. The shortest AFK timeout is 60 s, so a member is moved
/// at most one tick after their timeout.
const AFK_SWEEP_TICK: Duration = Duration::from_secs(15);

/// Moves attempted per tick. Each is a handful of SFU RPCs; whatever is left
/// over stays in the due range and is read first on the next tick.
const MAX_MOVES_PER_TICK: usize = 25;

/// Index entries read per tick.
const AFK_SWEEP_PAGE: usize = 500;

/// Lifetime of the move claim. It must outlive the move's 10 s `moved_to:`
/// marker (`voice::set_user_moved_to_voice`) and [`AFK_MOVE_TIMEOUT`]: while
/// it stands, no replica can move the same member again, including off a
/// claim their client re-posts before it has left the old channel.
const AFK_MOVE_CLAIM_TTL_SECS: usize = 30;

/// Bound on one move (P2-15). Shorter than the claim, so a move that hangs is
/// abandoned before a second replica could win the claim and duplicate it.
const AFK_MOVE_TIMEOUT: Duration = Duration::from_secs(20);

/// After a policy refusal the claim is re-expired to this, and the entry is
/// requeued as `AfkRequeue::Refused` (the same 300 s): a member who cannot
/// connect to the AFK channel is asked about again every five minutes, not
/// every tick.
const AFK_REFUSAL_BACKOFF_SECS: usize = 300;

/// A repeated log line is written at WARN once per this period per (server,
/// kind), and at DEBUG in between.
const AFK_LOG_THROTTLE: Duration = Duration::from_secs(3600);

/// The shortest AFK timeout the sweep acts on (the shortest of
/// `Server::AFK_TIMEOUT_CHOICES`).
const MIN_AFK_TIMEOUT_SECS: u32 = 60;

fn epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// Whether a claim has run its course.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdleDue {
    Due,
    /// The deadline is still ahead.
    NotYet,
    /// The claim predates the member's current join: it belongs to an earlier
    /// call and says nothing about this one.
    Stale,
    /// Cannot be decided: no `joined_at:` to check the claim against, or a
    /// timeout below [`MIN_AFK_TIMEOUT_SECS`]. Never due, and never `NotYet`
    /// either, because there is no deadline to wait for.
    Skip,
}

/// `now >= since + timeout`, in milliseconds, once the claim is known to
/// belong to the current join. The route clamps `since` to `joined_at`, so
/// `since < joined_at` only happens for a claim written before this join.
fn is_due(since_ms: i64, timeout_secs: u32, joined_at_ms: Option<i64>, now_ms: i64) -> IdleDue {
    let Some(joined_at_ms) = joined_at_ms else {
        return IdleDue::Skip;
    };

    if since_ms < joined_at_ms {
        return IdleDue::Stale;
    }

    if timeout_secs < MIN_AFK_TIMEOUT_SECS {
        return IdleDue::Skip;
    }

    if now_ms >= since_ms.saturating_add(i64::from(timeout_secs) * 1000) {
        IdleDue::Due
    } else {
        IdleDue::NotYet
    }
}

/// Screen sharing, camera or recording: the member is doing something the
/// sweep must not interrupt, however idle their input is (I-15, P2-13). These
/// flags are written by voice-ingress from SFU track events and by the
/// recording route, not by the idle claim.
fn media_active(state: &IdleState) -> bool {
    state.screensharing || state.camera || state.recording
}

/// Whether the state read after winning the claim still describes the member
/// the first read found due: same claim, same channel, same join, and still
/// no media. Anything else changed underneath us and is looked at again later.
fn still_due_after_claim(before: &IdleState, after: &IdleState) -> bool {
    after.claim == before.claim
        && after.pointer == before.pointer
        && after.joined_at_ms == before.joined_at_ms
        && !media_active(after)
}

/// What to do after a move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepAction {
    /// Nothing left to do: clear the claim and the index entry.
    Clear,
    /// Refused on policy grounds; the kind names the refusal.
    Refused(&'static str),
    /// Anything else, a timed-out move included.
    Other(&'static str),
}

/// The refusals a move raises as `Err` (Stage 1 I-17). They are answers
/// about the member or the AFK channel, not failures, and repeating them
/// every tick would change nothing.
fn refusal_kind(error: &ErrorType) -> Option<&'static str> {
    Some(match error {
        ErrorType::MissingPermission { .. } => "MissingPermission",
        ErrorType::NotAVoiceChannel => "NotAVoiceChannel",
        ErrorType::UnknownChannel => "UnknownChannel",
        ErrorType::CannotJoinCall => "CannotJoinCall",
        ErrorType::VideoCallFull { .. } => "VideoCallFull",
        ErrorType::MlsCallFull { .. } => "MlsCallFull",
        ErrorType::UnknownNode => "UnknownNode",
        _ => return None,
    })
}

/// Classify what `move_user_to_voice_channel_expecting` returned.
fn sweep_action(result: &Result<VoiceMoveOutcome>) -> SweepAction {
    match result {
        Ok(VoiceMoveOutcome::Moved { .. })
        | Ok(VoiceMoveOutcome::AlreadyPresent)
        | Ok(VoiceMoveOutcome::NotConnected) => SweepAction::Clear,
        Err(error) => match refusal_kind(&error.error_type) {
            Some(kind) => SweepAction::Refused(kind),
            None => SweepAction::Other("move failed"),
        },
    }
}

/// [`sweep_action`] for a move bounded by [`AFK_MOVE_TIMEOUT`]. A timeout is
/// `Other`: whether the abandoned move got anywhere is unknown, so the claim
/// is left to expire and the entry is looked at again in 30 s.
fn timed_sweep_action(
    outcome: &std::result::Result<Result<VoiceMoveOutcome>, Elapsed>,
) -> SweepAction {
    match outcome {
        Ok(result) => sweep_action(result),
        Err(_) => SweepAction::Other("move timed out"),
    }
}

/// Per-(server, kind) log throttle, held by [`task`] for the life of the
/// process. The same idea as the voice teardown's `TEARDOWN_FALLBACK_LOGGED`
/// latch: a condition that repeats every tick is written at WARN once and at
/// DEBUG after that, here re-armed hourly and per server so one misconfigured
/// server cannot hide another.
#[derive(Debug, Default)]
struct LogThrottle {
    logged_at: HashMap<(String, &'static str), Instant>,
}

impl LogThrottle {
    /// `true` if nothing was logged for (server, kind) within the throttle
    /// period, and records `now` if so.
    fn first_in_window(&mut self, server_id: &str, kind: &'static str, now: Instant) -> bool {
        let key = (server_id.to_string(), kind);

        match self.logged_at.get(&key) {
            Some(at) if now.saturating_duration_since(*at) < AFK_LOG_THROTTLE => false,
            _ => {
                self.logged_at.insert(key, now);
                true
            }
        }
    }

    /// Forget expired entries, so servers that stopped misbehaving do not
    /// accumulate.
    fn prune(&mut self, now: Instant) {
        self.logged_at
            .retain(|_, at| now.saturating_duration_since(*at) < AFK_LOG_THROTTLE);
    }
}

/// Log at WARN once per throttle period per (server, kind), DEBUG otherwise.
/// Never Sentry: none of these is a defect in this process.
fn log_throttled(
    throttle: &mut LogThrottle,
    server_id: &str,
    kind: &'static str,
    message: impl FnOnce() -> String,
) {
    if throttle.first_in_window(server_id, kind, Instant::now()) {
        log::warn!("{} (repeats logged at debug for an hour)", message());
    } else {
        log::debug!("{}", message());
    }
}

/// `afk_move_claim:{user}:{server}` — the only Redis key this file spells.
fn afk_move_claim_key(user_id: &str, server_id: &str) -> String {
    format!("afk_move_claim:{user_id}:{server_id}")
}

/// Take the move claim: `SET afk_move_claim:{user}:{server} 1 NX EX 30`.
/// `true` if this call set it. Never released: it expires, and until it does
/// no replica moves this member again.
///
/// `SetOptions`, `ExistenceCheck` and `SetExpiry` are the redis-rs fork's
/// (`523b293`: `commands/mod.rs:2076-2125`, `types.rs:49-68`). The reply is
/// `OK` or nil, which the fork decodes as `true` / `false`
/// (`types.rs:1281-1308`).
async fn claim_afk_move(user_id: &str, server_id: &str) -> Result<bool> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    conn.set_options(
        afk_move_claim_key(user_id, server_id),
        1,
        SetOptions::default()
            .conditional_set(ExistenceCheck::NX)
            .with_expiration(SetExpiry::EX(AFK_MOVE_CLAIM_TTL_SECS)),
    )
    .await
    .to_internal_error()
}

/// After a policy refusal: keep the claim for the backoff, so no replica
/// retries the same refused move before the entry comes due again.
async fn back_off_claim(user_id: &str, server_id: &str) -> Result<()> {
    let mut conn = get_connection()
        .await
        .map_err(|_| create_error!(InternalError))?;

    conn.expire(
        afk_move_claim_key(user_id, server_id),
        AFK_REFUSAL_BACKOFF_SECS,
    )
    .await
    .to_internal_error()
}

/// A server's AFK configuration, as far as the sweep can use it.
#[derive(Debug, Clone)]
enum AfkConfig {
    Usable {
        channel: Channel,
        timeout_secs: u32,
    },
    /// Nothing to move anyone into; the reason is logged.
    Unusable(&'static str),
    /// The server or the channel could not be read.
    Unreadable,
}

/// Resolve-then-check, never trust: the AFK pointer is validated only when
/// it is written, and the channel can be deleted or lose its voice
/// information afterwards (`Server::validate_afk_channel`).
async fn resolve_afk_config(db: &Database, server_id: &str) -> AfkConfig {
    let server = match db.fetch_server(server_id).await {
        Ok(server) => server,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return AfkConfig::Unusable("the server no longer exists")
        }
        Err(_) => return AfkConfig::Unreadable,
    };

    let (Some(channel_id), Some(timeout_secs)) = (server.afk_channel_id, server.afk_timeout) else {
        return AfkConfig::Unusable("no AFK channel or no AFK timeout");
    };

    if timeout_secs < MIN_AFK_TIMEOUT_SECS {
        return AfkConfig::Unusable("the AFK timeout is below 60 s");
    }

    let channel = match db.fetch_channel(&channel_id).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return AfkConfig::Unusable("the AFK channel no longer exists")
        }
        Err(_) => return AfkConfig::Unreadable,
    };

    if channel.server() != Some(server_id) {
        return AfkConfig::Unusable("the AFK channel is not in this server");
    }

    if channel.voice().is_none() {
        return AfkConfig::Unusable("the AFK channel is not a voice channel");
    }

    AfkConfig::Usable {
        channel,
        timeout_secs,
    }
}

/// One tick's cache of resolved server configs: a server with fifty idle
/// members costs one `fetch_server` and one `fetch_channel` per tick, not
/// fifty. Dropped at the end of the tick, so a config change is picked up on
/// the next one.
#[derive(Default)]
struct TickCache {
    configs: HashMap<String, AfkConfig>,
}

impl TickCache {
    async fn afk_config(&mut self, db: &Database, server_id: &str) -> AfkConfig {
        if let Some(config) = self.configs.get(server_id) {
            return config.clone();
        }

        let config = resolve_afk_config(db, server_id).await;
        self.configs.insert(server_id.to_string(), config.clone());
        config
    }
}

/// What happened to one index entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Candidate {
    /// Removed from the index: unparseable, or its claim is gone.
    Dropped,
    /// Claim and index entry cleared: nothing to do for this member.
    Cleared,
    /// Put back for later, without a move.
    Requeued(AfkRequeue),
    /// A move was attempted, with this result.
    MoveAttempted(SweepAction),
}

/// Remove an entry from the index, leaving any claim key to its TTL.
async fn drop_entry(member: &str, server_id: &str, throttle: &mut LogThrottle) -> Candidate {
    if let Err(error) = drop_idle_member(member).await {
        log_throttled(throttle, server_id, "index write failed", || {
            format!("AFK sweep: could not remove {member} from the idle index: {error}")
        });
    }

    Candidate::Dropped
}

/// Forget a member's claim: the key and its index entry.
async fn clear_entry(user_id: &str, server_id: &str, throttle: &mut LogThrottle) -> Candidate {
    if let Err(error) = clear_afk_since(user_id, server_id).await {
        log_throttled(throttle, server_id, "index write failed", || {
            format!("AFK sweep: could not clear the idle claim of {user_id}: {error}")
        });
    }

    Candidate::Cleared
}

/// Put an entry back in the index at the score `requeue_score` gives it.
/// The ONLY place this file writes a score: every requeue goes through
/// `requeue_score`, so none can leave an entry inside the range the sweep
/// just read.
async fn requeue_entry(
    member: &str,
    server_id: &str,
    r: AfkRequeue,
    since_ms: i64,
    timeout_secs: u32,
    now_ms: i64,
    throttle: &mut LogThrottle,
) -> Candidate {
    let written = match requeue_score(r, since_ms, timeout_secs, now_ms) {
        Some(score) => requeue_idle_member(member, score).await,
        None => drop_idle_member(member).await,
    };

    if let Err(error) = written {
        log_throttled(throttle, server_id, "index write failed", || {
            format!("AFK sweep: could not requeue {member} ({r:?}): {error}")
        });
    }

    Candidate::Requeued(r)
}

/// One index entry, in the order the plan pins (Wave 5b-2, "Sweep (crond)").
/// Every cheap reason not to move comes before the claim, the claim comes
/// before the re-read, and the re-read comes before the move.
async fn process_candidate(
    db: &Database,
    voice_client: &VoiceClient,
    member: &str,
    cache: &mut TickCache,
    throttle: &mut LogThrottle,
) -> Candidate {
    let now_ms = epoch_ms();

    let Some((user_id, server_id)) = parse_afk_idle_member(member) else {
        log_throttled(throttle, "", "unparseable member", || {
            format!("AFK sweep: dropping unparseable idle index member {member}")
        });
        return drop_entry(member, "", throttle).await;
    };

    // One MGET over the claim, the per-server pointer, `joined_at:` and the
    // three media flags.
    let state = match read_idle_state(user_id, server_id).await {
        Ok(state) => state,
        Err(error) => {
            log_throttled(throttle, server_id, "state read failed", || {
                format!("AFK sweep: could not read the idle state of {user_id}: {error}")
            });
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::InfraError,
                0,
                0,
                now_ms,
                throttle,
            )
            .await;
        }
    };

    // The claim expired or was withdrawn: only the index entry is left.
    let Some(claim) = state.claim.clone() else {
        return drop_entry(member, server_id, throttle).await;
    };

    // Not in a call in this server any more.
    let Some(pointer) = state.pointer.clone() else {
        return clear_entry(user_id, server_id, throttle).await;
    };

    let (afk_channel, timeout_secs) = match cache.afk_config(db, server_id).await {
        AfkConfig::Usable {
            channel,
            timeout_secs,
        } => (channel, timeout_secs),
        AfkConfig::Unusable(reason) => {
            log_throttled(throttle, server_id, "config", || {
                format!("AFK sweep: not moving anyone in server {server_id}: {reason}")
            });
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::Skip,
                claim.since_ms,
                0,
                now_ms,
                throttle,
            )
            .await;
        }
        AfkConfig::Unreadable => {
            log_throttled(throttle, server_id, "config read failed", || {
                format!("AFK sweep: could not read the AFK config of server {server_id}")
            });
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::InfraError,
                claim.since_ms,
                0,
                now_ms,
                throttle,
            )
            .await;
        }
    };

    // Already in the AFK channel. The move would answer `AlreadyPresent` too
    // (I-16), but only after the claim and a user fetch.
    if pointer == afk_channel.id() {
        return clear_entry(user_id, server_id, throttle).await;
    }

    // The claim names a channel they have since left.
    if claim.channel_id != pointer {
        return clear_entry(user_id, server_id, throttle).await;
    }

    match is_due(claim.since_ms, timeout_secs, state.joined_at_ms, now_ms) {
        IdleDue::Due => {}
        IdleDue::NotYet => {
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::NotYet,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await
        }
        IdleDue::Stale => return clear_entry(user_id, server_id, throttle).await,
        IdleDue::Skip => {
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::Skip,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await
        }
    }

    if media_active(&state) {
        return requeue_entry(
            member,
            server_id,
            AfkRequeue::Skip,
            claim.since_ms,
            timeout_secs,
            now_ms,
            throttle,
        )
        .await;
    }

    let user = match db.fetch_user(user_id).await {
        Ok(user) => user,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => {
            return clear_entry(user_id, server_id, throttle).await
        }
        Err(error) => {
            log_throttled(throttle, server_id, "user read failed", || {
                format!("AFK sweep: could not fetch user {user_id}: {error}")
            });
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::InfraError,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await;
        }
    };

    // Bots are never moved (I-19). The move function itself deliberately has
    // no bot check: a moderator may still move a bot by hand.
    if user.bot.is_some() {
        return clear_entry(user_id, server_id, throttle).await;
    }

    match claim_afk_move(user_id, server_id).await {
        Ok(true) => {}
        // Another replica is moving them, or a refusal backoff is running.
        Ok(false) => {
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::Skip,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await
        }
        Err(error) => {
            log_throttled(throttle, server_id, "claim failed", || {
                format!("AFK sweep: could not take the move claim for {user_id}: {error}")
            });
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::InfraError,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await;
        }
    }

    // Re-read under the claim. Between the first read and the claim the
    // member may have become active (the claim withdrawn), rejoined, moved,
    // or started sharing; any of those and the move is not made.
    let fresh = match read_idle_state(user_id, server_id).await {
        Ok(fresh) if still_due_after_claim(&state, &fresh) => fresh,
        Ok(_) => {
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::Skip,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await
        }
        Err(error) => {
            log_throttled(throttle, server_id, "state read failed", || {
                format!("AFK sweep: could not re-read the idle state of {user_id}: {error}")
            });
            return requeue_entry(
                member,
                server_id,
                AfkRequeue::InfraError,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await;
        }
    };

    // The source the move must find them in: the channel of the claim just
    // re-read under the move claim (audit A2). `still_due_after_claim` has
    // already required it to be the same claim as the first read's, which
    // named the live pointer; a missing one cannot get here, and is skipped
    // rather than moved without an expectation.
    let Some(fresh_claim) = fresh.claim.as_ref() else {
        return requeue_entry(
            member,
            server_id,
            AfkRequeue::Skip,
            claim.since_ms,
            timeout_secs,
            now_ms,
            throttle,
        )
        .await;
    };

    // Awaited, never propagated: a refusal is an `Err`, and one member's
    // refusal must not end the tick for every other server (I-17). With the
    // expected source, a member who switched channels since the re-read
    // answers `NotConnected` (cleared below) instead of being pulled out of
    // the channel they just chose.
    let outcome = tokio::time::timeout(
        AFK_MOVE_TIMEOUT,
        move_user_to_voice_channel_expecting(
            db,
            voice_client,
            &user,
            &afk_channel,
            &fresh_claim.channel_id,
        ),
    )
    .await;

    let action = timed_sweep_action(&outcome);
    match action {
        SweepAction::Clear => {
            clear_entry(user_id, server_id, throttle).await;
        }
        SweepAction::Refused(kind) => {
            if let Err(error) = back_off_claim(user_id, server_id).await {
                log_throttled(throttle, server_id, "claim failed", || {
                    format!("AFK sweep: could not extend the move claim for {user_id}: {error}")
                });
            }
            log_throttled(throttle, server_id, kind, || {
                format!(
                    "AFK sweep: moving {user_id} into {} in server {server_id} was refused \
                     ({kind}); retrying in {AFK_REFUSAL_BACKOFF_SECS} s",
                    afk_channel.id()
                )
            });
            requeue_entry(
                member,
                server_id,
                AfkRequeue::Refused,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await;
        }
        SweepAction::Other(kind) => {
            let detail = match &outcome {
                Ok(Err(error)) => error.to_string(),
                _ => format!("no answer within {} s", AFK_MOVE_TIMEOUT.as_secs()),
            };
            log_throttled(throttle, server_id, kind, || {
                format!(
                    "AFK sweep: moving {user_id} in server {server_id} failed ({kind}): {detail}"
                )
            });
            requeue_entry(
                member,
                server_id,
                AfkRequeue::InfraError,
                claim.since_ms,
                timeout_secs,
                now_ms,
                throttle,
            )
            .await;
        }
    }

    Candidate::MoveAttempted(action)
}

/// What one tick did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TickSummary {
    /// The kill switch was off: nothing was read.
    disabled: bool,
    /// The index could not be read.
    read_failed: bool,
    examined: usize,
    /// Entries left in the due range for the next tick by the move cap.
    deferred: usize,
    dropped: usize,
    cleared: usize,
    requeued: usize,
    moves_attempted: usize,
    moves_settled: usize,
    moves_refused: usize,
    moves_failed: usize,
    panicked: usize,
}

impl TickSummary {
    fn record(&mut self, candidate: Candidate) {
        match candidate {
            Candidate::Dropped => self.dropped += 1,
            Candidate::Cleared => self.cleared += 1,
            Candidate::Requeued(_) => self.requeued += 1,
            Candidate::MoveAttempted(action) => {
                self.moves_attempted += 1;
                match action {
                    SweepAction::Clear => self.moves_settled += 1,
                    SweepAction::Refused(_) => self.moves_refused += 1,
                    SweepAction::Other(_) => self.moves_failed += 1,
                }
            }
        }
    }
}

/// The kill switch's direction (audit B5): `features.afk_auto_move == true`
/// (the embedded default) means the sweep runs, `false` means it does not.
/// `run_tick` decides only through this.
fn sweep_enabled(features: &Features) -> bool {
    features.afk_auto_move
}

/// One pass over the due part of the index. Never fails: every error is
/// logged and handled per candidate, and a panicking candidate is caught and
/// requeued rather than taking the task (and its 60 s restart) with it.
async fn run_tick(
    db: &Database,
    voice_client: &VoiceClient,
    throttle: &mut LogThrottle,
) -> TickSummary {
    let mut summary = TickSummary::default();

    // The kill switch, read here on every tick rather than once in `task`.
    // Off means nothing is read, claimed or moved. Restart-only all the same:
    // the config sources are frozen into the process at first access.
    if !sweep_enabled(&revolt_config::config().await.features) {
        summary.disabled = true;
        return summary;
    }

    throttle.prune(Instant::now());

    let now_ms = epoch_ms();
    let members = match due_idle_members(now_ms, AFK_SWEEP_PAGE).await {
        Ok(members) => members,
        Err(error) => {
            log_throttled(throttle, "", "index read failed", || {
                format!("AFK sweep: could not read the idle index: {error}")
            });
            summary.read_failed = true;
            return summary;
        }
    };

    let mut cache = TickCache::default();

    for (index, member) in members.iter().enumerate() {
        // A panicked candidate counts too: it may have got as far as a move.
        if summary.moves_attempted + summary.panicked >= MAX_MOVES_PER_TICK {
            summary.deferred = members.len() - index;
            break;
        }

        summary.examined += 1;

        let candidate = AssertUnwindSafe(process_candidate(
            db,
            voice_client,
            member,
            &mut cache,
            throttle,
        ))
        .catch_unwind()
        .await;

        match candidate {
            Ok(candidate) => summary.record(candidate),
            Err(_) => {
                summary.panicked += 1;
                log::error!("AFK sweep: processing {member} panicked; retrying it later");

                let server_id = parse_afk_idle_member(member)
                    .map(|(_, server_id)| server_id)
                    .unwrap_or("");
                requeue_entry(
                    member,
                    server_id,
                    AfkRequeue::InfraError,
                    0,
                    0,
                    epoch_ms(),
                    throttle,
                )
                .await;
            }
        }
    }

    summary
}

/// AFK auto-move (AFK-channel plan, Wave 5b-2): moves members whose idle
/// claim has outlived their server's AFK timeout into its AFK channel.
///
/// Never returns, like `prune_remote_control_grants::task`. A task that
/// returns is logged at ERROR by `cron_task_wrapper` and restarted 60 s later,
/// so a deployment with no LiveKit nodes (nobody in a call, nothing to move)
/// logs that once at INFO and idles instead. The node list is config, read
/// once per process, so only a restart can change it.
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    let voice_client = VoiceClient::from_revolt_config().await;

    if !voice_client.is_enabled() {
        log::info!("AFK sweep: voice is not configured; idling");
        loop {
            sleep(AFK_SWEEP_TICK).await;
        }
    }

    let mut throttle = LogThrottle::default();
    let mut disabled_logged = false;

    loop {
        // Never propagate from inside this loop: `cron_task_wrapper` sleeps
        // 60 s before restarting a task that returns, which would stall every
        // server's sweep over one failure. `run_tick` returns a summary, not
        // a `Result`, for the same reason.
        let summary = run_tick(&db, &voice_client, &mut throttle).await;

        if summary.disabled {
            if !disabled_logged {
                log::info!("AFK sweep: features.afk_auto_move is off; not moving anyone");
                disabled_logged = true;
            }
        } else if summary.moves_attempted > 0 || summary.panicked > 0 {
            log::info!(
                "AFK sweep: examined {}, moves attempted {} (settled {}, refused {}, failed {}), \
                 panicked {}, deferred {}",
                summary.examined,
                summary.moves_attempted,
                summary.moves_settled,
                summary.moves_refused,
                summary.moves_failed,
                summary.panicked,
                summary.deferred
            );
        }

        sleep(AFK_SWEEP_TICK).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("afk_sweep.rs");
    const MAIN: &str = include_str!("../main.rs");

    /// This file above its test module.
    fn production() -> &'static str {
        SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("the file has a test module")
    }

    /// The braces as escapes: `voice::tests::shipping_sources` (revolt-database)
    /// strips every `#[cfg(test)]` item from the workspace by brace-matching,
    /// and a bare brace character here would leave this module unclosed.
    const OPEN: char = '\u{7b}';
    const CLOSE: char = '\u{7d}';

    /// The `{ ... }` body that follows the first `needle`.
    fn braced_body<'a>(source: &'a str, needle: &str) -> &'a str {
        let start = source
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not found"));
        let open = start + source[start..].find(OPEN).expect("a body");
        let mut depth = 0usize;

        for (offset, ch) in source[open..].char_indices() {
            match ch {
                OPEN => depth += 1,
                CLOSE => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[open..=open + offset];
                    }
                }
                _ => {}
            }
        }

        panic!("unbalanced body after {needle}");
    }

    /// The call that starts at the first `needle` (which ends in `(`), up to
    /// and including its matching `)`.
    fn braced_call<'a>(source: &'a str, needle: &str) -> &'a str {
        let start = source
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} not found"));
        let mut depth = 0usize;

        for (offset, ch) in source[start..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[start..=start + offset];
                    }
                }
                _ => {}
            }
        }

        panic!("unbalanced call after {needle}");
    }

    /// `text` without its `//` comments.
    fn code_only(text: &str) -> String {
        text.lines()
            .map(|line| line.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// `text` without any whitespace, for needles rustfmt may wrap.
    fn compact(text: &str) -> String {
        text.chars().filter(|ch| !ch.is_whitespace()).collect()
    }

    fn process_candidate_body() -> String {
        code_only(braced_body(production(), "async fn process_candidate("))
    }

    fn run_tick_body() -> String {
        code_only(braced_body(production(), "async fn run_tick("))
    }

    fn error(error_type: ErrorType) -> Result<VoiceMoveOutcome> {
        Err(revolt_result::Error {
            error_type,
            location: String::new(),
        })
    }

    /// Deleting the registration AND `pub mod afk_sweep;` deletes this test
    /// with the rest of the module, so the gate reads the test COUNT as well.
    #[test]
    fn the_sweep_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration = "cron_task_wrapper(afk_sweep::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the AFK sweep exactly once inside join!("
        );
        assert_eq!(MAIN.matches("afk_sweep::task").count(), 1);
    }

    /// The one move call (audit A2: the variant that takes the expected
    /// source, the only move entry point since S-3 RB-1).
    const MOVE_CALL: &str = "move_user_to_voice_channel_expecting(";

    /// The move is called once in the whole sweep, from `process_candidate`.
    /// (The S-3 cleanup deleted the plain move, so the ban on it that used to
    /// sit here matched nothing; it is retargeted at the file-wide call
    /// count, which a second move call anywhere in the sweep turns red.)
    #[test]
    fn the_move_is_awaited_and_never_propagated() {
        let body = process_candidate_body();

        assert_eq!(body.matches(MOVE_CALL).count(), 1);
        assert_eq!(
            code_only(production()).matches(MOVE_CALL).count(),
            1,
            "the sweep moves from exactly one place"
        );
        let after_call = &body[body.find(MOVE_CALL).unwrap()..];
        let after_await =
            &after_call[after_call.find(".await").expect("the move is awaited") + ".await".len()..];

        assert!(
            after_await.trim_start().starts_with(';'),
            "the move must end in `.await;`, found {:?}",
            &after_await[..after_await.len().min(40)]
        );
    }

    #[test]
    fn task_and_run_tick_never_propagate() {
        for (name, body) in [
            (
                "task",
                code_only(braced_body(production(), "pub async fn task(")),
            ),
            ("run_tick", run_tick_body()),
        ] {
            assert!(
                !body.contains('?'),
                "`{name}` must not use `?` (one failure would stall every server's sweep)"
            );
        }
    }

    /// `task` never returns, voice or no voice (the `prune_remote_control_grants`
    /// precedent): `cron_task_wrapper` logs a returned task at ERROR and
    /// restarts it every 60 s. Without voice it idles.
    #[test]
    fn task_never_returns() {
        let body = code_only(braced_body(production(), "pub async fn task("));

        assert!(!body.contains("return"), "`task` must never return");
        assert!(
            !body.contains("Ok("),
            "`task` must never finish with a value"
        );
        assert!(!body.contains("log::error!"));

        let disabled = braced_body(&body, "if !voice_client.is_enabled()");
        assert!(
            compact(disabled).contains("loop{sleep(AFK_SWEEP_TICK).await;}"),
            "without voice `task` idles: {disabled}"
        );
    }

    #[test]
    fn sweep_action_backs_off_on_every_policy_refusal() {
        let refusals = [
            (
                ErrorType::MissingPermission {
                    permission: "Connect".to_string(),
                },
                "MissingPermission",
            ),
            (ErrorType::NotAVoiceChannel, "NotAVoiceChannel"),
            (ErrorType::UnknownChannel, "UnknownChannel"),
            (ErrorType::CannotJoinCall, "CannotJoinCall"),
            (ErrorType::VideoCallFull { max: 30 }, "VideoCallFull"),
            (ErrorType::MlsCallFull { max: 100 }, "MlsCallFull"),
            (ErrorType::UnknownNode, "UnknownNode"),
        ];
        for (error_type, kind) in refusals {
            assert_eq!(sweep_action(&error(error_type)), SweepAction::Refused(kind));
        }

        for other in [ErrorType::InternalError, ErrorType::NotFound] {
            assert_eq!(
                sweep_action(&error(other)),
                SweepAction::Other("move failed")
            );
        }

        for settled in [
            VoiceMoveOutcome::Moved {
                node: "n".to_string(),
                from: "c".to_string(),
            },
            VoiceMoveOutcome::AlreadyPresent,
            VoiceMoveOutcome::NotConnected,
        ] {
            assert_eq!(sweep_action(&Ok(settled)), SweepAction::Clear);
        }
    }

    #[tokio::test]
    async fn a_timed_out_move_is_other() {
        let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .expect_err("a pending future times out");

        assert_eq!(
            timed_sweep_action(&Err(elapsed)),
            SweepAction::Other("move timed out")
        );
        assert_eq!(
            timed_sweep_action(&Ok(Ok(VoiceMoveOutcome::NotConnected))),
            SweepAction::Clear
        );
        assert_eq!(
            timed_sweep_action(&Ok(error(ErrorType::CannotJoinCall))),
            SweepAction::Refused("CannotJoinCall")
        );
    }

    /// P2-1: every non-clear arm requeues, and every requeue goes through
    /// `requeue_score`.
    #[test]
    fn every_non_clear_outcome_is_requeued_through_requeue_score() {
        let source = code_only(production());
        let requeue = code_only(braced_body(production(), "async fn requeue_entry("));

        assert!(requeue.contains("requeue_score(r, since_ms, timeout_secs, now_ms)"));
        assert_eq!(
            source.matches("requeue_idle_member(").count(),
            1,
            "the only score written must be the one `requeue_entry` computes"
        );
        assert!(requeue.contains("requeue_idle_member("));

        let body = process_candidate_body();
        for (arm, requeue) in [
            ("SweepAction::Refused(kind) =>", "AfkRequeue::Refused"),
            ("SweepAction::Other(kind) =>", "AfkRequeue::InfraError"),
        ] {
            let arm_body = braced_body(&body, arm);
            assert!(
                arm_body.contains("requeue_entry(") && arm_body.contains(requeue),
                "{arm} must requeue as {requeue}: {arm_body}"
            );
        }
        assert!(braced_body(&body, "SweepAction::Refused(kind) =>").contains("back_off_claim("));
        assert!(braced_body(&body, "SweepAction::Clear =>").contains("clear_entry("));
    }

    #[test]
    fn the_claim_is_set_nx_with_an_expiry() {
        assert_eq!(afk_move_claim_key("U", "S"), "afk_move_claim:U:S");

        let claim = compact(&code_only(braced_body(
            production(),
            "async fn claim_afk_move(",
        )));
        assert!(claim.contains("ExistenceCheck::NX"));
        assert!(claim.contains("SetExpiry::EX(AFK_MOVE_CLAIM_TTL_SECS)"));
        assert!(!claim.contains("ExistenceCheck::XX"));

        let back_off = compact(&code_only(braced_body(
            production(),
            "async fn back_off_claim(",
        )));
        assert!(back_off
            .contains(".expire(afk_move_claim_key(user_id,server_id),AFK_REFUSAL_BACKOFF_SECS"));
    }

    /// P2-15: the move is bounded, by the constant the claim TTL is checked
    /// against in `the_claim_outlives_the_markers_and_the_move`.
    #[test]
    fn the_move_is_bounded_by_a_timeout() {
        assert!(compact(&process_candidate_body()).contains(&format!(
            "tokio::time::timeout(AFK_MOVE_TIMEOUT,{MOVE_CALL}"
        )));
    }

    /// Audit A2: the move names the source it was decided about, taken from
    /// the claim RE-READ under the move claim, never the first read's (which
    /// a member may have switched away from in between). The S-3 cleanup
    /// made the expectation a required `&str`, so the `!call.contains("None")`
    /// that used to guard against "no expectation" could no longer fail and
    /// was deleted; the exact argument list below pins the source.
    #[test]
    fn the_move_expects_the_reread_claims_channel() {
        let body = process_candidate_body();
        let call = compact(braced_call(&body, MOVE_CALL));

        assert_eq!(
            call,
            format!("{MOVE_CALL}db,voice_client,&user,&afk_channel,&fresh_claim.channel_id,)")
        );

        let fresh_claim = body
            .find("let Some(fresh_claim) = fresh.claim.as_ref() else")
            .expect("the expectation comes from the re-read state");
        assert!(body.find("let fresh = match read_idle_state(").unwrap() < fresh_claim);
        assert!(fresh_claim < body.find(MOVE_CALL).unwrap());
    }

    /// The arguments that follow each CALL of `name(` in `code` (definitions,
    /// `fn name(`, excluded), whitespace removed, first 40 characters.
    fn call_arguments(code: &str, name: &str) -> Vec<String> {
        code.match_indices(name)
            .filter(|(at, _)| !code[..*at].ends_with("fn "))
            .map(|(at, _)| compact(&code[at + name.len()..]).chars().take(40).collect())
            .collect()
    }

    /// Audit R-5: every `(user, server)` pair reaches its callee in that
    /// order, and every index write is given the raw index member. Every
    /// argument here is a `&str`, so a swap compiles and, without this, ships:
    /// a swapped first read finds every claim gone and moves nobody, a
    /// swapped clear leaves the entry in the due range for good. The precedent
    /// is revolt-database's `the_idle_reads_and_clear_pass_user_then_server`.
    #[test]
    fn every_idle_call_passes_user_then_server() {
        let code = code_only(production());

        // How the pair is derived: from the index member, user first.
        assert_eq!(
            code.matches("let Some((user_id, server_id)) = parse_afk_idle_member(member) else")
                .count(),
            1
        );
        assert_eq!(code.matches("parse_afk_idle_member(").count(), 2);
        assert!(compact(&run_tick_body())
            .contains("parse_afk_idle_member(member).map(|(_,server_id)|server_id)"));

        // Each (user, server) callee, with its exact number of call sites.
        for (name, sites) in [
            ("read_idle_state(", 2),
            ("clear_afk_since(", 1),
            ("clear_entry(", 7),
            ("claim_afk_move(", 1),
            ("back_off_claim(", 1),
            ("afk_move_claim_key(", 2),
        ] {
            let calls = call_arguments(&code, name);
            assert_eq!(calls.len(), sites, "{name} call sites: {calls:?}");
            for arguments in calls {
                assert!(
                    arguments.starts_with("user_id,server_id"),
                    "{name} must be passed (user_id, server_id): {arguments}"
                );
            }
        }

        // The index is written with the member exactly as it was read.
        for (name, first) in [
            ("drop_entry(", "member,"),
            ("requeue_entry(", "member,server_id,"),
        ] {
            let calls = call_arguments(&code, name);
            assert!(!calls.is_empty(), "no {name} call");
            for arguments in calls {
                assert!(
                    arguments.starts_with(first),
                    "{name} must start with ({first}): {arguments}"
                );
            }
        }
        assert_eq!(
            code.matches("requeue_idle_member(member, score)").count(),
            1
        );
        assert_eq!(code.matches("drop_idle_member(member)").count(), 2);
    }

    /// Audit B7: the re-read's RESULT is what gates the move.
    #[test]
    fn the_reread_result_gates_the_move() {
        assert_eq!(
            process_candidate_body()
                .matches("Ok(fresh) if still_due_after_claim(&state, &fresh) => fresh,")
                .count(),
            1
        );
    }

    #[test]
    fn the_claim_precedes_the_reread_which_precedes_the_move() {
        let body = process_candidate_body();
        let claim = body.find("claim_afk_move(").expect("the claim");
        let reads: Vec<usize> = body
            .match_indices("read_idle_state(")
            .map(|(at, _)| at)
            .collect();
        let movement = body.find(MOVE_CALL).expect("the move");

        assert_eq!(reads.len(), 2, "one read, one re-read under the claim");
        assert!(reads[0] < claim, "the first read precedes the claim");
        assert!(claim < reads[1], "the re-read follows the claim");
        assert!(reads[1] < movement, "the move follows the re-read");
    }

    #[test]
    fn the_claim_outlives_the_markers_and_the_move() {
        // Against the marker's own constant (audit B10), not a copy of it.
        assert!(AFK_MOVE_CLAIM_TTL_SECS > revolt_database::voice::MOVED_TO_MARKER_TTL_SECS);
        assert_eq!(AFK_MOVE_CLAIM_TTL_SECS, 30);
        assert!(AFK_MOVE_TIMEOUT < Duration::from_secs(AFK_MOVE_CLAIM_TTL_SECS as u64));
        assert_eq!(AFK_MOVE_TIMEOUT, Duration::from_secs(20));

        // The claim backoff and the index backoff after a refusal agree.
        assert_eq!(AFK_REFUSAL_BACKOFF_SECS, 300);
        assert_eq!(
            requeue_score(AfkRequeue::Refused, 0, 60, 0),
            Some(AFK_REFUSAL_BACKOFF_SECS as i64 * 1000)
        );
    }

    /// AFK S-3 D-5 (P2-7): the move's SFU budget, stated against the REAL
    /// `pub` constants of the transport. A retyped `3` here would stay green
    /// whatever the transport did.
    ///
    /// Every SFU call is bounded by `SFU_CALL_TIMEOUT`, and a node's breaker
    /// trips after two consecutive timeouts and then fails its calls fast for
    /// `SFU_BREAKER_WINDOW`. So a node costs a move at most two timeouts per
    /// window, and the bounds hold ONLY with the breaker:
    ///
    /// - The whole move (one listing and the evictions on the source's node,
    ///   one `create_room` on the destination's, the remote-control calls on
    ///   the source's): at most two distinct nodes, two timeouts each, inside
    ///   `AFK_MOVE_TIMEOUT`.
    /// - Mint to emit: only the remote-control release sits between
    ///   `create_token` and the event that hands the token over, up to four
    ///   calls, all on the node the source call's grants were made on. One
    ///   node, two timeouts, inside `MOVE_TOKEN_TTL`; and the window outlasts
    ///   the token, so a breaker that trips inside it never lets a half-open
    ///   probe add a third.
    ///
    /// The plan's text asked for `2 * 2 * SFU_CALL_TIMEOUT < MOVE_TOKEN_TTL`
    /// for the second bound. That is FALSE at the contract values (12 s
    /// against 10 s), so it is not pinned: it would describe grants of one
    /// source call spread over two nodes, which a call's single node pin
    /// does not produce. Recorded as a deviation in the Wave C report.
    #[test]
    fn the_move_fits_its_sfu_budget_with_the_breaker() {
        use revolt_database::voice::{MOVE_TOKEN_TTL, SFU_BREAKER_WINDOW, SFU_CALL_TIMEOUT};

        assert!(
            2 * 2 * SFU_CALL_TIMEOUT < AFK_MOVE_TIMEOUT,
            "two nodes x two timeouts must fit the move: {SFU_CALL_TIMEOUT:?} vs \
             {AFK_MOVE_TIMEOUT:?}"
        );
        assert!(
            2 * SFU_CALL_TIMEOUT < MOVE_TOKEN_TTL,
            "one node x two timeouts must fit between mint and emit: {SFU_CALL_TIMEOUT:?} \
             vs {MOVE_TOKEN_TTL:?}"
        );
        assert!(
            SFU_BREAKER_WINDOW >= MOVE_TOKEN_TTL,
            "a breaker tripped between mint and emit stays open for the token's life: \
             {SFU_BREAKER_WINDOW:?} vs {MOVE_TOKEN_TTL:?}"
        );
    }

    #[test]
    fn cheap_short_circuits_precede_the_claim() {
        let body = process_candidate_body();
        let claim = body.find("claim_afk_move(").expect("the claim");

        for needle in [
            "if pointer == afk_channel.id()",
            "if claim.channel_id != pointer",
            "if media_active(&state)",
            "if user.bot.is_some()",
        ] {
            let at = body
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} is missing"));
            assert!(at < claim, "{needle} must precede the claim");
        }
    }

    #[test]
    fn is_due_cases() {
        let joined = Some(1_000_000);

        // Exactly at the deadline is due; a millisecond before is not.
        assert_eq!(is_due(1_000_000, 60, joined, 1_060_000), IdleDue::Due);
        assert_eq!(is_due(1_000_000, 60, joined, 1_059_999), IdleDue::NotYet);
        assert_eq!(is_due(1_000_000, 3600, joined, 4_600_000), IdleDue::Due);
        assert_eq!(is_due(1_000_000, 3600, joined, 4_599_999), IdleDue::NotYet);

        // A claim from before this join is stale, however old.
        assert_eq!(is_due(999_999, 60, joined, i64::MAX), IdleDue::Stale);
        // Since == joined_at is the clamp itself, not stale.
        assert_eq!(is_due(1_000_000, 60, joined, 1_000_000), IdleDue::NotYet);

        // No join time: never due, and never NotYet (no deadline to wait for).
        assert_eq!(is_due(0, 60, None, i64::MAX), IdleDue::Skip);
        // A timeout below 60 s: never due.
        assert_eq!(is_due(1_000_000, 59, joined, i64::MAX), IdleDue::Skip);
        assert_eq!(is_due(1_000_000, 0, joined, i64::MAX), IdleDue::Skip);

        // No overflow on an absurd `since`.
        assert_eq!(is_due(i64::MAX, 3600, Some(0), 0), IdleDue::NotYet);
    }

    #[test]
    fn each_candidate_runs_inside_catch_unwind() {
        let body = compact(&run_tick_body());

        assert!(body.contains("AssertUnwindSafe(process_candidate("));
        assert!(body.contains(".catch_unwind()"));
    }

    #[test]
    fn the_tick_is_bounded() {
        assert_eq!(MAX_MOVES_PER_TICK, 25);
        assert_eq!(AFK_SWEEP_PAGE, 500);
        assert_eq!(AFK_SWEEP_TICK, Duration::from_secs(15));
        assert_eq!(MIN_AFK_TIMEOUT_SECS, 60);
        assert_eq!(AFK_LOG_THROTTLE, Duration::from_secs(3600));

        assert!(run_tick_body().contains(">= MAX_MOVES_PER_TICK"));
    }

    /// Audit B5: the switch's direction. `true` (the embedded default, pinned
    /// by value in revolt-config) runs the sweep; `false` stops it.
    #[tokio::test]
    async fn the_kill_switch_runs_the_sweep_only_when_true() {
        let mut features = revolt_config::config().await.features;

        features.afk_auto_move = true;
        assert!(sweep_enabled(&features), "afk_auto_move = true must sweep");
        features.afk_auto_move = false;
        assert!(!sweep_enabled(&features), "afk_auto_move = false must not");
    }

    #[test]
    fn the_kill_switch_is_read_inside_the_tick() {
        let body = run_tick_body();
        let switch = body
            .find("sweep_enabled(")
            .expect("run_tick reads the kill switch");

        assert!(switch < body.find("due_idle_members(").unwrap());
        // Decided only through `sweep_enabled`, and off leads straight out.
        assert!(compact(&body).contains(
            "if!sweep_enabled(&revolt_config::config().await.features){summary.disabled=true;returnsummary;}"
        ));
        assert!(!body.contains("afk_auto_move"));
        // Not read once in `task` and handed down: `task` only names it in a
        // log line.
        assert!(!code_only(braced_body(production(), "pub async fn task("))
            .contains(".features.afk_auto_move"));
    }

    /// The upper bound of the index read is `now`: anything earlier leaves
    /// due members unread, anything later moves people early.
    #[test]
    fn the_index_read_is_bounded_by_now() {
        let body = compact(&run_tick_body());

        assert!(body.contains("letnow_ms=epoch_ms();"));
        assert!(body.contains("due_idle_members(now_ms,AFK_SWEEP_PAGE)"));
        assert_eq!(body.matches("due_idle_members(").count(), 1);
    }

    /// P2-7: every idle key comes from `afk_idle`. The needles are split so
    /// this test does not match itself.
    #[test]
    fn no_idle_key_string_is_built_here() {
        for needle in [
            concat!("\"joined", "_at:"),
            concat!("\"screen", "sharing:"),
            concat!("\"cam", "era:"),
            concat!("\"record", "ing:"),
            concat!("\"afk", "_since:"),
        ] {
            assert!(
                !SOURCE.contains(needle),
                "{needle} is spelled in afk_sweep.rs"
            );
        }
    }

    #[test]
    fn media_blocks_the_move() {
        let quiet = IdleState::default();
        assert!(!media_active(&quiet));

        for flag in 0..3 {
            let mut state = quiet.clone();
            match flag {
                0 => state.screensharing = true,
                1 => state.camera = true,
                _ => state.recording = true,
            }
            assert!(media_active(&state), "flag {flag}");
        }
    }

    #[test]
    fn the_reread_must_match_the_first_read() {
        use revolt_database::voice::afk_idle::AfkIdleClaim;

        let before = IdleState {
            claim: Some(AfkIdleClaim {
                channel_id: "C".to_string(),
                since_ms: 5,
            }),
            pointer: Some("C".to_string()),
            joined_at_ms: Some(1),
            ..Default::default()
        };
        assert!(still_due_after_claim(&before, &before.clone()));

        let changes: [fn(&mut IdleState); 6] = [
            |s| s.claim = None,
            |s| s.claim.as_mut().unwrap().since_ms = 6,
            |s| s.pointer = Some("D".to_string()),
            |s| s.joined_at_ms = Some(2),
            |s| s.recording = true,
            |s| s.screensharing = true,
        ];
        for (index, change) in changes.iter().enumerate() {
            let mut after = before.clone();
            change(&mut after);
            assert!(!still_due_after_claim(&before, &after), "change {index}");
        }
    }

    #[test]
    fn the_log_throttle_is_per_server_and_kind_and_hourly() {
        let mut throttle = LogThrottle::default();
        let start = Instant::now();

        assert!(throttle.first_in_window("S", "CannotJoinCall", start));
        assert!(!throttle.first_in_window(
            "S",
            "CannotJoinCall",
            start + Duration::from_secs(3599)
        ));
        assert!(throttle.first_in_window("S", "UnknownNode", start));
        assert!(throttle.first_in_window("T", "CannotJoinCall", start));
        assert!(throttle.first_in_window("S", "CannotJoinCall", start + AFK_LOG_THROTTLE));

        throttle.prune(start + AFK_LOG_THROTTLE + AFK_LOG_THROTTLE);
        assert!(throttle.logged_at.is_empty());
    }
}
