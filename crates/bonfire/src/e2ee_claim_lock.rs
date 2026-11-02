//! Live-claim lock for an E2EE device (multi-device plan D4)
//!
//! At most one SESSION is live on a (user, device) at a time. An accepted
//! device claim takes `e2ee_claim:{user}:{device}` = `{session}:{conn}` with
//! a TTL; the connection refreshes it while it lives and releases it when it
//! ends. A claim while another session holds the lock is refused; the same
//! session on another connection (a reconnect overlap) takes it over.
//!
//! Every write is a compare-and-set in Lua, so a connection can only extend
//! or delete its own value: a refresh after a takeover cannot steal the lock
//! back, and a late release cannot free a successor's lock. Redis being
//! unavailable fails open to the old last-writer-wins behaviour (owner
//! decision O4); the lock protects availability and integrity between the
//! user's own installs, not confidentiality.

use std::{
    future::Future,
    sync::LazyLock,
    time::{Duration, Instant},
};

use redis_kiss::{
    get_connection,
    redis::{FromRedisValue, Script},
    AsyncCommands,
};

/// How long the lock outlives the socket's idle timeout. A connection that
/// dies without releasing (a crashed node) frees its device this long after
/// it would have been dropped as silent.
pub const CLAIM_LOCK_GRACE: Duration = Duration::from_secs(30);

/// Least time between two refreshes driven by inbound frames
pub const CLAIM_LOCK_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// Bound on one Redis round trip; a slower one counts as a Redis error
const LOCK_OP_TIMEOUT: Duration = Duration::from_secs(2);

/// `reason` of a claim refused because another session holds the lock
pub const REASON_HELD_ELSEWHERE: &str = "held_elsewhere";

/// `reason` of a claim refused because the device was removed (plan D8)
pub const REASON_REMOVED: &str = "removed";

/// Lock TTL for a socket dropped after `idle_timeout` of silence
pub fn claim_lock_ttl(idle_timeout: Duration) -> Duration {
    idle_timeout + CLAIM_LOCK_GRACE
}

/// Redis key of the live claim on (user, device)
pub fn lock_key(user_id: &str, device_id: &str) -> String {
    format!("e2ee_claim:{user_id}:{device_id}")
}

/// Lock value naming one connection of one session
pub fn lock_value(session_id: &str, conn_id: &str) -> String {
    format!("{session_id}:{conn_id}")
}

/// The session part of a lock value: everything before the last `:`.
/// Connection ids never contain one. Must match `ACQUIRE_LUA`.
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

/// The compare-and-set operations on the lock. Implemented over Redis by
/// [`RedisClaimLock`]; the tests use an in-memory store with the same
/// semantics.
pub trait ClaimLockStore: Clone + Send + Sync + 'static {
    /// Take `key` for `value` with `ttl` if it is absent or its holder's
    /// session is `session_id`; otherwise report the holder
    fn acquire(
        &self,
        key: &str,
        value: &str,
        session_id: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<Acquire, LockError>> + Send;

    /// Reset `key`'s TTL iff it still holds `value`; whether it did
    fn refresh(
        &self,
        key: &str,
        value: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<bool, LockError>> + Send;

    /// Delete `key` iff it still holds `value`; whether it did
    fn release(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, LockError>> + Send;

    /// The current lock value, if any
    fn holder(&self, key: &str) -> impl Future<Output = Result<Option<String>, LockError>> + Send;
}

/// `KEYS[1]` the lock key; `ARGV[1]` our value, `ARGV[2]` our session id,
/// `ARGV[3]` the TTL in milliseconds. Returns `{1, ""}` when the lock is
/// ours (it was absent or our session's), `{0, holder}` when another
/// session holds it. The session part is cut at the last `:`, as in
/// [`holder_session`].
const ACQUIRE_LUA: &str = r#"
local current = redis.call('GET', KEYS[1])
if current then
  local holder = string.match(current, '^(.*):[^:]*$') or current
  if holder ~= ARGV[2] then
    return {0, current}
  end
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[3])
return {1, ''}
"#;

/// `KEYS[1]` the lock key; `ARGV[1]` our value, `ARGV[2]` the TTL in
/// milliseconds. Extends the TTL only while the value is still ours.
const REFRESH_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0
"#;

/// `KEYS[1]` the lock key; `ARGV[1]` our value. Deletes only our own value.
const RELEASE_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;

/// `Script` sends EVALSHA and loads the source on NOSCRIPT
static ACQUIRE: LazyLock<Script> = LazyLock::new(|| Script::new(ACQUIRE_LUA));
static REFRESH: LazyLock<Script> = LazyLock::new(|| Script::new(REFRESH_LUA));
static RELEASE: LazyLock<Script> = LazyLock::new(|| Script::new(RELEASE_LUA));

/// The lock in the shared Redis that presence and slowmode already use
#[derive(Clone, Copy, Debug, Default)]
pub struct RedisClaimLock;

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

impl ClaimLockStore for RedisClaimLock {
    async fn acquire(
        &self,
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

    async fn refresh(&self, key: &str, value: &str, ttl: Duration) -> Result<bool, LockError> {
        let ttl_ms = ttl.as_millis().to_string();
        let refreshed: i64 = invoke(&REFRESH, key, &[value, &ttl_ms]).await?;
        Ok(refreshed == 1)
    }

    async fn release(&self, key: &str, value: &str) -> Result<bool, LockError> {
        let released: i64 = invoke(&RELEASE, key, &[value]).await?;
        Ok(released == 1)
    }

    async fn holder(&self, key: &str) -> Result<Option<String>, LockError> {
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
}

/// Verdict on a claim whose proof already verified
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimDecision {
    /// This connection holds the lock
    Accepted,
    /// Redis could not decide; accepted without a lock (owner decision O4)
    FailedOpen,
    /// Another session holds the lock; refuse with `held_elsewhere`
    HeldElsewhere { holder_session: String },
}

impl ClaimDecision {
    pub fn is_accepted(&self) -> bool {
        !matches!(self, ClaimDecision::HeldElsewhere { .. })
    }
}

/// The lock a connection holds
#[derive(Debug)]
struct Held {
    device_id: String,
    key: String,
    last_refresh: Instant,
}

/// One connection's side of the lock. Dropping it releases whatever it
/// still holds, so every exit of the connection worker releases.
pub struct ConnectionClaim<S: ClaimLockStore> {
    store: S,
    user_id: String,
    session_id: String,
    value: String,
    ttl: Duration,
    held: Option<Held>,
}

impl<S: ClaimLockStore> ConnectionClaim<S> {
    /// A connection of `session_id` with a fresh random connection id
    pub fn new(store: S, user_id: &str, session_id: &str, ttl: Duration) -> Self {
        let conn_id = format!("{:016x}", rand::random::<u64>());
        Self::with_conn_id(store, user_id, session_id, &conn_id, ttl)
    }

    fn with_conn_id(
        store: S,
        user_id: &str,
        session_id: &str,
        conn_id: &str,
        ttl: Duration,
    ) -> Self {
        ConnectionClaim {
            store,
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            value: lock_value(session_id, conn_id),
            ttl,
            held: None,
        }
    }

    /// Take the lock on `device_id` for a claim whose proof VERIFIED (never
    /// before: a keyless token must learn nothing about who holds it). A
    /// lock this connection holds on another device is released first.
    pub async fn acquire(&mut self, device_id: &str, now: Instant) -> ClaimDecision {
        if self
            .held
            .as_ref()
            .is_some_and(|held| held.device_id != device_id)
        {
            self.release().await;
        }

        let key = lock_key(&self.user_id, device_id);
        match self
            .store
            .acquire(&key, &self.value, &self.session_id, self.ttl)
            .await
        {
            Ok(Acquire::Acquired) => {
                self.held = Some(Held {
                    device_id: device_id.to_string(),
                    key,
                    last_refresh: now,
                });
                ClaimDecision::Accepted
            }
            Ok(Acquire::HeldBy(value)) => {
                // Whatever this connection held on the device is gone
                self.held = None;
                let holder_session = holder_session(&value).to_string();
                info!(
                    "E2EE claim refused (held_elsewhere): user={} device={} holder_session={} session={}",
                    self.user_id, device_id, holder_session, self.session_id
                );
                ClaimDecision::HeldElsewhere { holder_session }
            }
            Err(err) => {
                warn!(
                    "E2EE claim lock unavailable, accepting without it: user={} device={} session={}: {}",
                    self.user_id, device_id, self.session_id, err.0
                );
                ClaimDecision::FailedOpen
            }
        }
    }

    /// Refresh the held lock if the last refresh is at least
    /// [`CLAIM_LOCK_REFRESH_INTERVAL`] old (driven by inbound frames)
    pub async fn refresh_if_due(&mut self, now: Instant) {
        let due = self.held.as_ref().is_some_and(|held| {
            now.saturating_duration_since(held.last_refresh) >= CLAIM_LOCK_REFRESH_INTERVAL
        });
        if due {
            self.refresh(now).await;
        }
    }

    /// Refresh the held lock now (the ping tick). Compare-and-set only: a
    /// lock another connection took over is let go, never taken back.
    pub async fn refresh(&mut self, now: Instant) {
        let Some(held) = self.held.as_mut() else {
            return;
        };

        // Stamped even on an error, so an outage is not retried per frame
        held.last_refresh = now;
        match self.store.refresh(&held.key, &self.value, self.ttl).await {
            Ok(true) => {}
            Ok(false) => {
                debug!(
                    "E2EE claim lock no longer ours: user={} device={} session={}",
                    self.user_id, held.device_id, self.session_id
                );
                self.held = None;
            }
            Err(err) => warn!(
                "E2EE claim lock refresh failed: user={} device={} session={}: {}",
                self.user_id, held.device_id, self.session_id, err.0
            ),
        }
    }

    /// Release the held lock (compare-and-delete)
    pub async fn release(&mut self) {
        let Some(held) = self.held.take() else {
            return;
        };

        if let Err(err) = self.store.release(&held.key, &self.value).await {
            warn!(
                "E2EE claim lock release failed, it expires with its TTL: user={} device={}: {}",
                self.user_id, held.device_id, err.0
            );
        }
    }

    /// Whether this connection's SESSION may act for `device_id` (honour an
    /// acknowledgement, drain the queue): the lock's session is ours or,
    /// when the lock is absent or unreadable, `bound_session` (the device
    /// row's `last_session_id`, only awaited then) is ours. Sessions are
    /// compared, not connections, so a reconnect overlap keeps its rights.
    pub async fn may_act<F>(&self, device_id: &str, bound_session: F) -> bool
    where
        F: Future<Output = Option<String>>,
    {
        match self.store.holder(&lock_key(&self.user_id, device_id)).await {
            Ok(Some(value)) => holder_session(&value) == self.session_id,
            Ok(None) => bound_session.await.as_deref() == Some(self.session_id.as_str()),
            Err(err) => {
                debug!(
                    "E2EE claim lock unreadable, checking the device binding: user={} device={}: {}",
                    self.user_id, device_id, err.0
                );
                bound_session.await.as_deref() == Some(self.session_id.as_str())
            }
        }
    }
}

impl<S: ClaimLockStore> Drop for ConnectionClaim<S> {
    fn drop(&mut self) {
        let Some(held) = self.held.take() else {
            return;
        };

        let store = self.store.clone();
        let value = self.value.clone();
        let user_id = self.user_id.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Err(err) = store.release(&held.key, &value).await {
                        warn!(
                            "E2EE claim lock release failed, it expires with its TTL: user={} device={}: {}",
                            user_id, held.device_id, err.0
                        );
                    }
                });
            }
            Err(_) => warn!(
                "No runtime to release an E2EE claim lock, it expires with its TTL: user={} device={}",
                user_id, held.device_id
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use super::*;

    const TTL: Duration = Duration::from_secs(150);

    /// In-memory lock with the scripts' semantics and a clock the test moves
    #[derive(Clone)]
    struct FakeLock(Arc<Mutex<FakeState>>);

    struct FakeState {
        now: Instant,
        entries: HashMap<String, (String, Instant)>,
        failing: bool,
        refreshes: usize,
    }

    impl FakeLock {
        fn new() -> Self {
            FakeLock(Arc::new(Mutex::new(FakeState {
                now: Instant::now(),
                entries: HashMap::new(),
                failing: false,
                refreshes: 0,
            })))
        }

        fn now(&self) -> Instant {
            self.0.lock().unwrap().now
        }

        fn advance(&self, by: Duration) {
            self.0.lock().unwrap().now += by;
        }

        fn fail(&self, failing: bool) {
            self.0.lock().unwrap().failing = failing;
        }

        fn refreshes(&self) -> usize {
            self.0.lock().unwrap().refreshes
        }

        fn get(&self, key: &str) -> Option<String> {
            let mut state = self.0.lock().unwrap();
            state.live(key)
        }
    }

    impl FakeState {
        /// The value at `key`, dropping it once expired
        fn live(&mut self, key: &str) -> Option<String> {
            let now = self.now;
            match self.entries.get(key) {
                Some((_, expires)) if now >= *expires => {
                    self.entries.remove(key);
                    None
                }
                Some((value, _)) => Some(value.clone()),
                None => None,
            }
        }

        fn check(&self) -> Result<(), LockError> {
            if self.failing {
                Err(LockError("injected".to_string()))
            } else {
                Ok(())
            }
        }
    }

    impl ClaimLockStore for FakeLock {
        async fn acquire(
            &self,
            key: &str,
            value: &str,
            session_id: &str,
            ttl: Duration,
        ) -> Result<Acquire, LockError> {
            let mut state = self.0.lock().unwrap();
            state.check()?;
            if let Some(current) = state.live(key) {
                if holder_session(&current) != session_id {
                    return Ok(Acquire::HeldBy(current));
                }
            }
            let expires = state.now + ttl;
            state.entries.insert(key.to_string(), (value.to_string(), expires));
            Ok(Acquire::Acquired)
        }

        async fn refresh(&self, key: &str, value: &str, ttl: Duration) -> Result<bool, LockError> {
            let mut state = self.0.lock().unwrap();
            state.check()?;
            state.refreshes += 1;
            if state.live(key).as_deref() == Some(value) {
                let expires = state.now + ttl;
                state.entries.insert(key.to_string(), (value.to_string(), expires));
                return Ok(true);
            }
            Ok(false)
        }

        async fn release(&self, key: &str, value: &str) -> Result<bool, LockError> {
            let mut state = self.0.lock().unwrap();
            state.check()?;
            if state.live(key).as_deref() == Some(value) {
                state.entries.remove(key);
                return Ok(true);
            }
            Ok(false)
        }

        async fn holder(&self, key: &str) -> Result<Option<String>, LockError> {
            let mut state = self.0.lock().unwrap();
            state.check()?;
            Ok(state.live(key))
        }
    }

    fn conn(lock: &FakeLock, session: &str, conn_id: &str) -> ConnectionClaim<FakeLock> {
        ConnectionClaim::with_conn_id(lock.clone(), "U", session, conn_id, TTL)
    }

    fn key(device: &str) -> String {
        lock_key("U", device)
    }

    /// A DB fallback that records whether it was consulted
    fn bound(
        session: Option<&str>,
        polled: &Arc<AtomicBool>,
    ) -> impl Future<Output = Option<String>> {
        let session = session.map(str::to_string);
        let polled = polled.clone();
        async move {
            polled.store(true, Ordering::SeqCst);
            session
        }
    }

    #[test]
    fn key_value_and_session_part() {
        assert_eq!(lock_key("U1", "d1"), "e2ee_claim:U1:d1");
        assert_eq!(lock_value("S1", "c1"), "S1:c1");
        assert_eq!(holder_session("S1:c1"), "S1");
        assert_eq!(holder_session("a:b:c1"), "a:b");
        assert_eq!(holder_session("bare"), "bare");
    }

    #[tokio::test]
    async fn d4_refuses_another_session() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        let mut other = conn(&lock, "S2", "c2");

        assert_eq!(first.acquire("D", lock.now()).await, ClaimDecision::Accepted);
        let refused = other.acquire("D", lock.now()).await;
        assert_eq!(
            refused,
            ClaimDecision::HeldElsewhere {
                holder_session: "S1".to_string()
            }
        );
        assert!(!refused.is_accepted());
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));

        // The refused connection holds nothing, so its drop frees nothing
        drop(other);
        tokio::task::yield_now().await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));
    }

    #[tokio::test]
    async fn d4_same_session_reconnect_takes_over() {
        let lock = FakeLock::new();
        let mut old = conn(&lock, "S1", "c1");
        let mut new = conn(&lock, "S1", "c2");

        assert_eq!(old.acquire("D", lock.now()).await, ClaimDecision::Accepted);
        assert_eq!(new.acquire("D", lock.now()).await, ClaimDecision::Accepted);
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c2"));
    }

    #[tokio::test]
    async fn d4_expiry_frees_the_lock() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        let mut other = conn(&lock, "S2", "c2");

        assert!(first.acquire("D", lock.now()).await.is_accepted());
        lock.advance(TTL - Duration::from_millis(1));
        assert!(!other.acquire("D", lock.now()).await.is_accepted());
        lock.advance(Duration::from_millis(1));
        assert_eq!(other.acquire("D", lock.now()).await, ClaimDecision::Accepted);
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S2:c2"));
    }

    #[tokio::test]
    async fn d4_refresh_extends_our_own_lock() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        let mut other = conn(&lock, "S2", "c2");

        assert!(first.acquire("D", lock.now()).await.is_accepted());
        lock.advance(TTL - Duration::from_secs(1));
        first.refresh(lock.now()).await;
        lock.advance(Duration::from_secs(2));
        assert!(!other.acquire("D", lock.now()).await.is_accepted());
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));
    }

    #[tokio::test]
    async fn d4_refresh_after_a_takeover_does_not_steal() {
        let lock = FakeLock::new();
        let mut old = conn(&lock, "S1", "c1");
        let mut new = conn(&lock, "S1", "c2");

        assert!(old.acquire("D", lock.now()).await.is_accepted());
        lock.advance(Duration::from_secs(10));
        assert!(new.acquire("D", lock.now()).await.is_accepted());

        lock.advance(Duration::from_secs(20));
        old.refresh(lock.now()).await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c2"));

        // Nor did it extend the successor's TTL, which still runs from the
        // takeover
        lock.advance(TTL - Duration::from_secs(20));
        assert_eq!(lock.get(&key("D")), None);

        // Having let go, the old connection stops refreshing
        let before = lock.refreshes();
        old.refresh(lock.now()).await;
        assert_eq!(lock.refreshes(), before);
    }

    #[tokio::test]
    async fn d4_inbound_refresh_is_throttled() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        assert!(first.acquire("D", lock.now()).await.is_accepted());

        lock.advance(CLAIM_LOCK_REFRESH_INTERVAL - Duration::from_secs(1));
        first.refresh_if_due(lock.now()).await;
        assert_eq!(lock.refreshes(), 0);

        lock.advance(Duration::from_secs(1));
        first.refresh_if_due(lock.now()).await;
        assert_eq!(lock.refreshes(), 1);

        first.refresh_if_due(lock.now()).await;
        assert_eq!(lock.refreshes(), 1);
    }

    #[tokio::test]
    async fn d4_release_only_deletes_our_own_value() {
        let lock = FakeLock::new();
        let mut old = conn(&lock, "S1", "c1");
        let mut new = conn(&lock, "S1", "c2");

        assert!(old.acquire("D", lock.now()).await.is_accepted());
        assert!(new.acquire("D", lock.now()).await.is_accepted());

        old.release().await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c2"));

        new.release().await;
        assert_eq!(lock.get(&key("D")), None);
    }

    #[tokio::test]
    async fn d4_drop_releases_the_lock() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        assert!(first.acquire("D", lock.now()).await.is_accepted());

        drop(first);
        for _ in 0..100 {
            if lock.get(&key("D")).is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(lock.get(&key("D")), None, "dropping the connection left its lock");
    }

    #[tokio::test]
    async fn d4_proving_another_device_releases_the_old_lock_first() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        let mut other = conn(&lock, "S2", "c2");

        assert!(first.acquire("D1", lock.now()).await.is_accepted());
        assert!(first.acquire("D2", lock.now()).await.is_accepted());
        assert_eq!(lock.get(&key("D1")), None);
        assert_eq!(lock.get(&key("D2")).as_deref(), Some("S1:c1"));

        // Also when the new device is refused
        assert!(other.acquire("D3", lock.now()).await.is_accepted());
        assert!(!first.acquire("D3", lock.now()).await.is_accepted());
        assert_eq!(lock.get(&key("D2")), None);
    }

    #[tokio::test]
    async fn d4_redis_error_fails_open() {
        let lock = FakeLock::new();
        let mut other = conn(&lock, "S2", "c2");
        assert!(other.acquire("D", lock.now()).await.is_accepted());

        lock.fail(true);
        let mut first = conn(&lock, "S1", "c1");
        let decision = first.acquire("D", lock.now()).await;
        assert_eq!(decision, ClaimDecision::FailedOpen);
        assert!(decision.is_accepted());

        // An unreadable lock refers the gate to the device binding
        let polled = Arc::new(AtomicBool::new(false));
        assert!(first.may_act("D", bound(Some("S1"), &polled)).await);
        assert!(polled.load(Ordering::SeqCst));
        assert!(!first.may_act("D", bound(Some("S2"), &polled)).await);

        // A refresh or release during the outage is harmless
        first.refresh(lock.now()).await;
        first.release().await;
        lock.fail(false);
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S2:c2"));
    }

    /// Plan D4 / audit m4: acks and drains follow the lock's SESSION, and the
    /// device binding only when the lock is absent or unreadable
    #[tokio::test]
    async fn d4_ack_gate_matrix() {
        let lock = FakeLock::new();
        let ours = conn(&lock, "S1", "c1");

        // (lock value, lock readable, bound session, expected, DB consulted)
        let cases: [(Option<&str>, bool, Option<&str>, bool, bool); 10] = [
            // Our session holds it, on this or another connection
            (Some("S1:c1"), true, Some("S2"), true, false),
            (Some("S1:c9"), true, None, true, false),
            // Another session holds it: denied whatever the row says
            (Some("S2:c2"), true, Some("S1"), false, false),
            (Some("S10:c1"), true, Some("S1"), false, false),
            // No lock: the device binding decides
            (None, true, Some("S1"), true, true),
            (None, true, Some("S2"), false, true),
            (None, true, None, false, true),
            // Redis error: the device binding decides
            (Some("S2:c2"), false, Some("S1"), true, true),
            (Some("S1:c1"), false, Some("S2"), false, true),
            (None, false, None, false, true),
        ];

        for (value, readable, bound_to, expected, consulted) in cases {
            {
                let mut state = lock.0.lock().unwrap();
                state.entries.clear();
                if let Some(value) = value {
                    let expires = state.now + TTL;
                    state.entries.insert(key("D"), (value.to_string(), expires));
                }
                state.failing = !readable;
            }

            let polled = Arc::new(AtomicBool::new(false));
            let allowed = ours.may_act("D", bound(bound_to, &polled)).await;
            let label = format!("lock={value:?} readable={readable} bound={bound_to:?}");
            assert_eq!(allowed, expected, "{label}");
            assert_eq!(polled.load(Ordering::SeqCst), consulted, "DB consulted: {label}");
        }
        lock.fail(false);
    }

    /// The Lua scripts against the Redis the bonfire tests already use
    /// (`REDIS_URI`, default `redis://localhost`). Keys are unique to the run
    /// and deleted at the end.
    #[tokio::test]
    async fn d4_redis_scripts_keep_compare_and_set_semantics() {
        static RUN: AtomicUsize = AtomicUsize::new(0);
        let user = format!(
            "bb1test{:016x}{}",
            rand::random::<u64>(),
            RUN.fetch_add(1, Ordering::SeqCst)
        );
        let key = lock_key(&user, "D");
        let redis = RedisClaimLock;
        let ttl = Duration::from_secs(30);

        let task_key = key.clone();
        let outcome = async move {
            let key = task_key;
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), None);
            assert_eq!(
                redis.acquire(&key, "S1:c1", "S1", ttl).await.expect("acquire"),
                Acquire::Acquired
            );

            // The TTL is set on acquire
            let mut conn = get_connection().await.expect("redis").into_inner();
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 0 && pttl <= ttl.as_millis() as i64, "pttl {pttl}");

            // Another session is refused and learns the holder
            assert_eq!(
                redis.acquire(&key, "S2:c2", "S2", ttl).await.expect("acquire"),
                Acquire::HeldBy("S1:c1".to_string())
            );
            // A session id that merely starts with the holder's is another session
            assert_eq!(
                redis.acquire(&key, "S:c3", "S", ttl).await.expect("acquire"),
                Acquire::HeldBy("S1:c1".to_string())
            );

            // The same session on another connection takes over
            assert_eq!(
                redis.acquire(&key, "S1:c4", "S1", ttl).await.expect("acquire"),
                Acquire::Acquired
            );
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), Some("S1:c4"));

            // A stale refresh neither steals nor extends
            let _: () = conn.pexpire(&key, 5_000).await.expect("pexpire");
            assert!(!redis.refresh(&key, "S1:c1", ttl).await.expect("refresh"));
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), Some("S1:c4"));
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 0 && pttl <= 5_000, "a stale refresh extended the TTL: {pttl}");

            // The holder's refresh extends
            assert!(redis.refresh(&key, "S1:c4", ttl).await.expect("refresh"));
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 5_000 && pttl <= ttl.as_millis() as i64, "pttl {pttl}");

            // A stale release deletes nothing; the holder's deletes
            assert!(!redis.release(&key, "S1:c1").await.expect("release"));
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), Some("S1:c4"));
            assert!(redis.release(&key, "S1:c4").await.expect("release"));
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), None);

            // Absent: refresh and release are no-ops, acquire takes it
            assert!(!redis.refresh(&key, "S1:c4", ttl).await.expect("refresh"));
            assert!(!redis.release(&key, "S1:c4").await.expect("release"));
            assert_eq!(
                redis.acquire(&key, "S2:c2", "S2", ttl).await.expect("acquire"),
                Acquire::Acquired
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
}
