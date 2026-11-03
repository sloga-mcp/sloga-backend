//! Live-claim lock on an E2EE device: key format and compare-and-set
//! scripts (multi-device plan D4)
//!
//! `e2ee_claim:{user}:{device}` = `{session}:{conn}` names the one SESSION
//! live on a device. Bonfire takes, refreshes and releases it per
//! connection; delta's split publication (plan D5) deletes the old
//! device's lock when this session holds it, and its device removal reads
//! the locks to decide who may remove a device ([`decide_revoke`]). All of
//! them go through this module, so the format and the scripts cannot drift
//! apart.
//!
//! Every write is a Lua compare-and-set, so a caller only extends, takes
//! over or deletes a lock its own session holds. Callers treat a
//! [`LockError`] as "Redis could not decide" and fail open (owner decision
//! O4); the device removal instead falls back to the database's bindings.

use std::{future::Future, sync::LazyLock, time::Duration};

use redis_kiss::{
    get_connection,
    redis::{FromRedisValue, Script},
    AsyncCommands,
};

/// Bound on one Redis round trip; a slower one counts as a Redis error
pub const LOCK_OP_TIMEOUT: Duration = Duration::from_secs(2);

/// Redis key of the live claim on (user, device)
pub fn lock_key(user_id: &str, device_id: &str) -> String {
    format!("e2ee_claim:{user_id}:{device_id}")
}

/// Lock value naming one connection of one session
pub fn lock_value(session_id: &str, conn_id: &str) -> String {
    format!("{session_id}:{conn_id}")
}

/// The session part of a lock value: everything before the last `:`.
/// Connection ids never contain one. Must match the scripts' `HOLDER`.
pub fn holder_session(value: &str) -> &str {
    value.rsplit_once(':').map_or(value, |(session, _)| session)
}

/// A lock operation that could not reach a verdict
#[derive(Debug)]
pub struct LockError(pub String);

/// Outcome of one acquire attempt
#[derive(Debug, PartialEq, Eq)]
pub enum Acquire {
    /// The lock was absent, or held by the same session; it is ours now
    Acquired,
    /// Another session holds it; the full lock value
    HeldBy(String),
}

/// Outcome of one refresh attempt
#[derive(Debug, PartialEq, Eq)]
pub enum Refresh {
    /// Our session held it (this connection or a sibling); it holds our
    /// value now, with a fresh TTL
    Extended,
    /// No lock; nothing was written
    Absent,
    /// Another session holds it; left alone
    HeldElsewhere,
}

/// The session part of `current`, as [`holder_session`] cuts it
macro_rules! holder_lua {
    () => {
        "local holder = string.match(current, '^(.*):[^:]*$') or current\n"
    };
}

/// `KEYS[1]` the lock key; `ARGV[1]` our value, `ARGV[2]` our session id,
/// `ARGV[3]` the TTL in milliseconds. Returns `{1, ""}` when the lock is
/// ours (it was absent or our session's), `{0, holder}` when another
/// session holds it.
const ACQUIRE_LUA: &str = concat!(
    "local current = redis.call('GET', KEYS[1])\n",
    "if current then\n",
    holder_lua!(),
    "  if holder ~= ARGV[2] then\n",
    "    return {0, current}\n",
    "  end\n",
    "end\n",
    "redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])\n",
    "return {1, ''}\n",
);

/// `KEYS[1]` the lock key; `ARGV[1]` our value, `ARGV[2]` our session id,
/// `ARGV[3]` the TTL in milliseconds. Returns 1 when our session held it
/// (it holds our value now, TTL reset), 2 when it is absent, 0 when
/// another session holds it. Never creates the key and never touches
/// another session's.
const REFRESH_LUA: &str = concat!(
    "local current = redis.call('GET', KEYS[1])\n",
    "if not current then\n",
    "  return 2\n",
    "end\n",
    holder_lua!(),
    "if holder ~= ARGV[2] then\n",
    "  return 0\n",
    "end\n",
    "redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])\n",
    "return 1\n",
);

/// `KEYS[1]` the lock key; `ARGV[1]` our value. Deletes only our own value.
const RELEASE_LUA: &str = concat!(
    "if redis.call('GET', KEYS[1]) == ARGV[1] then\n",
    "  return redis.call('DEL', KEYS[1])\n",
    "end\n",
    "return 0\n",
);

/// `KEYS[1]` the lock key; `ARGV[1]` a session id. Deletes the lock iff
/// that session holds it, on whichever connection.
const RELEASE_SESSION_LUA: &str = concat!(
    "local current = redis.call('GET', KEYS[1])\n",
    "if not current then\n",
    "  return 0\n",
    "end\n",
    holder_lua!(),
    "if holder ~= ARGV[1] then\n",
    "  return 0\n",
    "end\n",
    "return redis.call('DEL', KEYS[1])\n",
);

/// `Script` sends EVALSHA and loads the source on NOSCRIPT
static ACQUIRE: LazyLock<Script> = LazyLock::new(|| Script::new(ACQUIRE_LUA));
static REFRESH: LazyLock<Script> = LazyLock::new(|| Script::new(REFRESH_LUA));
static RELEASE: LazyLock<Script> = LazyLock::new(|| Script::new(RELEASE_LUA));
static RELEASE_SESSION: LazyLock<Script> = LazyLock::new(|| Script::new(RELEASE_SESSION_LUA));

/// Run `script` under [`LOCK_OP_TIMEOUT`]. The connection is taken out of
/// the pool (`into_inner`), so one cut off by the timeout mid-reply is
/// dropped rather than handed to the next caller.
async fn invoke<T: FromRedisValue + Send>(
    script: &Script,
    key: &str,
    args: &[&str],
) -> Result<T, LockError> {
    let work = async {
        let mut conn = get_connection()
            .await
            .map_err(|err| LockError(format!("{err:?}")))?
            .into_inner();
        let mut invocation = script.prepare_invoke();
        invocation.key(key);
        for arg in args {
            invocation.arg(*arg);
        }
        invocation
            .invoke_async::<_, T>(&mut conn)
            .await
            .map_err(|err| LockError(err.to_string()))
    };

    tokio::time::timeout(LOCK_OP_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err(LockError("timed out".to_string())))
}

/// Take `key` for `value` with `ttl` if it is absent or its holder's
/// session is `session_id`; otherwise report the holder
pub async fn acquire(
    key: &str,
    value: &str,
    session_id: &str,
    ttl: Duration,
) -> Result<Acquire, LockError> {
    let ttl_ms = ttl.as_millis().to_string();
    let (taken, holder): (i64, String) =
        invoke(&ACQUIRE, key, &[value, session_id, &ttl_ms]).await?;

    Ok(if taken == 1 {
        Acquire::Acquired
    } else {
        Acquire::HeldBy(holder)
    })
}

/// Re-assert `value` with a fresh `ttl` while `session_id` holds `key`;
/// an absent lock is reported, not recreated
pub async fn refresh(
    key: &str,
    value: &str,
    session_id: &str,
    ttl: Duration,
) -> Result<Refresh, LockError> {
    let ttl_ms = ttl.as_millis().to_string();
    let outcome: i64 = invoke(&REFRESH, key, &[value, session_id, &ttl_ms]).await?;

    Ok(match outcome {
        1 => Refresh::Extended,
        2 => Refresh::Absent,
        _ => Refresh::HeldElsewhere,
    })
}

/// Delete `key` iff it still holds `value`; whether it did
pub async fn release(key: &str, value: &str) -> Result<bool, LockError> {
    let released: i64 = invoke(&RELEASE, key, &[value]).await?;
    Ok(released == 1)
}

/// Delete `key` iff `session_id` holds it, on any connection; whether it did
pub async fn release_held_by_session(key: &str, session_id: &str) -> Result<bool, LockError> {
    let released: i64 = invoke(&RELEASE_SESSION, key, &[session_id]).await?;
    Ok(released == 1)
}

/// The current lock value, if any
pub async fn holder(key: &str) -> Result<Option<String>, LockError> {
    let work = async {
        let mut conn = get_connection()
            .await
            .map_err(|err| LockError(format!("{err:?}")))?
            .into_inner();
        conn.get::<_, Option<String>>(key)
            .await
            .map_err(|err| LockError(err.to_string()))
    };

    tokio::time::timeout(LOCK_OP_TIMEOUT, work)
        .await
        .unwrap_or_else(|_| Err(LockError("timed out".to_string())))
}

/// Whether `session_id` may act for a device (honour an acknowledgement,
/// drain the queue), given the read of its lock: the lock's session is
/// `session_id` or, when the lock is absent or unreadable, `bound_session`
/// (the device row's `last_session_id`, only awaited then) is. Sessions
/// are compared, not connections, so a reconnect overlap keeps its rights.
pub async fn session_may_act<F>(
    lock: Result<Option<String>, LockError>,
    session_id: &str,
    bound_session: F,
) -> bool
where
    F: Future<Output = Option<String>>,
{
    match lock {
        Ok(Some(value)) => holder_session(&value) == session_id,
        Ok(None) | Err(_) => bound_session.await.as_deref() == Some(session_id),
    }
}

/// The removal route's read of the removed device's lock
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeLock {
    /// The lock is switched off (`[features.e2ee] claim_lock = false`):
    /// nothing was read
    Off,
    /// Redis could not answer
    Unreadable,
    /// No lock
    Absent,
    /// The session part of the lock's value
    HeldBy(String),
}

impl RevokeLock {
    /// Whether the lock was read; the other own devices' locks are read only
    /// then
    pub fn is_readable(&self) -> bool {
        matches!(self, RevokeLock::Absent | RevokeLock::HeldBy(_))
    }
}

/// Read `key` for the removal route; nothing at all while `claim_lock` is off
pub async fn read_for_revoke(claim_lock: bool, key: &str) -> RevokeLock {
    if !claim_lock {
        return RevokeLock::Off;
    }

    match holder(key).await {
        Ok(Some(value)) => RevokeLock::HeldBy(holder_session(&value).to_string()),
        Ok(None) => RevokeLock::Absent,
        Err(_) => RevokeLock::Unreadable,
    }
}

/// Whether `session_id` holds the live lock of one of `devices` (the
/// account's other devices). A lock that cannot be read counts as not held.
pub async fn session_holds_any<'a>(
    user_id: &str,
    devices: impl IntoIterator<Item = &'a str>,
    session_id: &str,
) -> bool {
    for device_id in devices {
        if let Ok(Some(value)) = holder(&lock_key(user_id, device_id)).await {
            if holder_session(&value) == session_id {
                return true;
            }
        }
    }
    false
}

/// What `DELETE /e2ee/keys/{device}` knows when it decides, all of it read
/// before anything is written
#[derive(Debug, Clone)]
pub struct RevokeFacts<'a> {
    /// The calling session
    pub caller_session: &'a str,
    /// The removed device's lock
    pub lock: RevokeLock,
    /// The removed device row's `last_session_id`
    pub bound_session: &'a str,
    /// Whether that session still exists (false for `""`)
    pub bound_session_exists: bool,
    /// Whether the caller holds the live lock of another of the account's
    /// devices; read only when [`RevokeLock::is_readable`]
    pub caller_holds_another_lock: bool,
    /// Whether another of the account's device rows is bound to the caller
    pub another_row_bound_to_caller: bool,
}

/// Whether the caller may remove the device (multi-device addendum A1):
/// - the lock is held by the caller: yes;
/// - held by another session: only if the caller holds the live lock of
///   another of the account's devices;
/// - absent: that, or the row is bound to the caller, or its binding is
///   dead (`""` or a session that no longer exists);
/// - unreadable, or switched off: from the database alone, the row is
///   bound to the caller, its binding is dead, or another of the account's
///   rows is bound to the caller.
///
/// A refusal writes nothing.
pub fn decide_revoke(facts: &RevokeFacts) -> bool {
    let bound_to_caller = facts.bound_session == facts.caller_session;
    let binding_dead = facts.bound_session.is_empty() || !facts.bound_session_exists;

    match &facts.lock {
        RevokeLock::HeldBy(holder) => {
            holder == facts.caller_session || facts.caller_holds_another_lock
        }
        RevokeLock::Absent => facts.caller_holds_another_lock || bound_to_caller || binding_dead,
        RevokeLock::Unreadable | RevokeLock::Off => {
            bound_to_caller || binding_dead || facts.another_row_bound_to_caller
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn key_value_and_session_part() {
        assert_eq!(lock_key("U1", "d1"), "e2ee_claim:U1:d1");
        assert_eq!(lock_value("S1", "c1"), "S1:c1");
        assert_eq!(holder_session("S1:c1"), "S1");
        assert_eq!(holder_session("a:b:c1"), "a:b");
        assert_eq!(holder_session("bare"), "bare");
    }

    /// `release_held_by_session` and the session-compare refresh against the
    /// Redis the tests already use (`REDIS_URI`). Keys are unique to the
    /// run and deleted at the end.
    #[tokio::test]
    async fn d4_session_scripts_against_redis() {
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let user = format!(
            "bftest{:016x}{}",
            rand::random::<u64>(),
            RUN.fetch_add(1, Ordering::SeqCst)
        );
        let key = lock_key(&user, "D");
        let ttl = Duration::from_secs(30);

        let task_key = key.clone();
        let outcome = async move {
            let key = task_key;

            // Absent: nothing to refresh, nothing to delete, nothing created
            assert_eq!(refresh(&key, "S1:c1", "S1", ttl).await.expect("refresh"), Refresh::Absent);
            assert!(!release_held_by_session(&key, "S1").await.expect("release"));
            assert_eq!(holder(&key).await.expect("holder"), None);

            // A sibling connection of the session holds it: refresh re-asserts
            // this connection's value with a fresh TTL
            assert_eq!(acquire(&key, "S1:c2", "S1", ttl).await.expect("acquire"), Acquire::Acquired);
            let mut conn = get_connection().await.expect("redis").into_inner();
            let _: () = conn.pexpire(&key, 5_000).await.expect("pexpire");
            assert_eq!(refresh(&key, "S1:c1", "S1", ttl).await.expect("refresh"), Refresh::Extended);
            assert_eq!(holder(&key).await.expect("holder").as_deref(), Some("S1:c1"));
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 5_000 && pttl <= ttl.as_millis() as i64, "pttl {pttl}");

            // Another session's lock: neither refreshed, extended nor deleted
            let _: () = conn.del(&key).await.expect("del");
            assert_eq!(acquire(&key, "S2:c9", "S2", ttl).await.expect("acquire"), Acquire::Acquired);
            let _: () = conn.pexpire(&key, 5_000).await.expect("pexpire");
            for session in ["S1", "S", "S2:c9"] {
                assert_eq!(
                    refresh(&key, &format!("{session}:c1"), session, ttl).await.expect("refresh"),
                    Refresh::HeldElsewhere
                );
                assert!(!release_held_by_session(&key, session).await.expect("release"));
            }
            assert_eq!(holder(&key).await.expect("holder").as_deref(), Some("S2:c9"));
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 0 && pttl <= 5_000, "another session's TTL was extended: {pttl}");

            // The holder's session deletes it, whichever connection holds it
            assert!(release_held_by_session(&key, "S2").await.expect("release"));
            assert_eq!(holder(&key).await.expect("holder"), None);

            // The gate: the lock's session, else the binding
            let unbound = async { Some(String::new()) };
            assert!(!session_may_act(holder(&key).await, "S2", unbound).await);
            assert!(session_may_act(Ok(None), "S2", async { Some("S2".to_string()) }).await);
            assert!(session_may_act(Ok(Some("S2:c1".into())), "S2", async { None }).await);
            assert!(
                !session_may_act(Ok(Some("S20:c1".into())), "S2", async { Some("S2".to_string()) })
                    .await
            );
            assert!(
                session_may_act(Err(LockError("x".into())), "S2", async { Some("S2".to_string()) })
                    .await
            );
        };
        let result = tokio::spawn(outcome).await;

        if let Ok(mut conn) = get_connection().await.map(|conn| conn.into_inner()) {
            let _: Result<(), _> = conn.del(&key).await;
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic.into_panic());
        }
    }

    /// Addendum A1, every row of its table. `S` calls, `H` is the other
    /// install's live session, `""` an unbound row
    #[test]
    fn revoke_decision_table() {
        use RevokeLock::{Absent, HeldBy, Off, Unreadable};

        let held = |session: &str| HeldBy(session.to_string());
        // (row, lock, bound, bound session exists, S holds another lock,
        //  another row bound to S, allowed)
        let cases: Vec<(&str, RevokeLock, &str, bool, bool, bool, bool)> = vec![
            // Refused twin, wiped or not: the other install holds the lock,
            // whatever the row says
            ("twin, lock elsewhere", held("H"), "H", true, false, false, false),
            ("twin, lock elsewhere, row names S", held("H"), "S", true, false, false, false),
            ("twin, lock elsewhere, dead binding", held("H"), "", false, false, false, false),
            ("twin, lock elsewhere, own row bound", held("H"), "H", true, false, true, false),
            // Twin retrying after the holder's lock lapsed: absent, bound to
            // the holder's live session
            ("twin, lock lapsed", Absent, "H", true, false, false, false),
            // Twin bound to an orphan or predecessor row, no live lock
            ("orphan row, lock elsewhere", held("H"), "H", true, false, true, false),
            ("orphan row, lock absent", Absent, "H", true, false, true, false),
            // The holder disabling its own device
            ("holder", held("S"), "S", true, false, false, true),
            ("holder, row moved", held("S"), "H", true, false, false, true),
            // Another own device removing T (S holds that device's lock)
            ("other device, lock elsewhere", held("H"), "H", true, true, false, true),
            ("other device, lock absent", Absent, "H", true, true, false, true),
            // T offline and bound to S, or its binding dead
            ("offline, bound to S", Absent, "S", true, false, false, true),
            ("offline, unbound", Absent, "", false, false, false, true),
            ("offline, bound to a gone session", Absent, "G", false, false, false, true),
            // Accepted regression: no live device, T's session alive
            ("no live device, T's session alive", Absent, "H", true, false, false, false),
            // Redis down: the database decides
            ("redis down, bound to S", Unreadable, "S", true, false, false, true),
            ("redis down, unbound", Unreadable, "", false, false, false, true),
            ("redis down, gone session", Unreadable, "G", false, false, false, true),
            ("redis down, own row bound", Unreadable, "H", true, false, true, true),
            ("redis down, bound elsewhere", Unreadable, "H", true, false, false, false),
            ("redis down, lock claim ignored", Unreadable, "H", true, true, false, false),
            // Switched off: the same database rule, no lock read
            ("off, bound to S", Off, "S", true, false, false, true),
            ("off, dead binding", Off, "", false, false, false, true),
            ("off, own row bound", Off, "H", true, false, true, true),
            ("off, bound elsewhere", Off, "H", true, false, false, false),
            ("off, lock claim ignored", Off, "H", true, true, false, false),
        ];

        for (row, lock, bound, exists, holds, own_row, allowed) in cases {
            let facts = RevokeFacts {
                caller_session: "S",
                lock,
                bound_session: bound,
                bound_session_exists: exists,
                caller_holds_another_lock: holds,
                another_row_bound_to_caller: own_row,
            };
            assert_eq!(decide_revoke(&facts), allowed, "{row}: {facts:?}");
        }
    }

    /// The removal route's lock reads against Redis: switched off it reads
    /// nothing (a lock left in Redis is not seen), and only a lock the
    /// caller's SESSION holds counts as holding another device
    #[tokio::test]
    async fn revoke_lock_reads_against_redis() {
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let user = format!(
            "aatest{:016x}{}",
            rand::random::<u64>(),
            RUN.fetch_add(1, Ordering::SeqCst)
        );
        let keys = [lock_key(&user, "T"), lock_key(&user, "D")];
        let ttl = Duration::from_secs(30);

        let task_user = user.clone();
        let outcome = async move {
            let user = task_user;
            let target = lock_key(&user, "T");

            assert_eq!(read_for_revoke(true, &target).await, RevokeLock::Absent);
            assert_eq!(acquire(&target, "H:c1", "H", ttl).await.expect("acquire"), Acquire::Acquired);
            assert_eq!(read_for_revoke(true, &target).await, RevokeLock::HeldBy("H".into()));
            assert_eq!(read_for_revoke(false, &target).await, RevokeLock::Off);

            assert!(!session_holds_any(&user, ["D"], "S").await, "no lock on D");
            assert_eq!(
                acquire(&lock_key(&user, "D"), "S:c2", "S", ttl).await.expect("acquire"),
                Acquire::Acquired
            );
            assert!(session_holds_any(&user, ["X", "D"], "S").await);
            assert!(!session_holds_any(&user, ["D"], "S2").await, "another session");
            assert!(!session_holds_any(&user, ["T"], "S").await, "T is H's");
            assert!(!session_holds_any(&user, [], "S").await);
        };
        let result = tokio::spawn(outcome).await;

        if let Ok(mut conn) = get_connection().await.map(|conn| conn.into_inner()) {
            for key in &keys {
                let _: Result<(), _> = conn.del(key).await;
            }
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic.into_panic());
        }
    }
}
