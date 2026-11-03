//! Live-claim lock for an E2EE device (multi-device plan D4)
//!
//! At most one SESSION is live on a (user, device) at a time. An accepted
//! device claim takes `e2ee_claim:{user}:{device}` = `{session}:{conn}` with
//! a TTL; the connection refreshes it while it lives and releases it when it
//! ends. A claim while another session holds the lock is refused; the same
//! session on another connection (a reconnect overlap) takes it over.
//!
//! Every write is a compare-and-set in Lua, so a connection can only extend
//! or delete its own session's lock: a refresh after another session took
//! the device cannot steal it back, and a late release cannot free a
//! successor's lock. Redis being unavailable fails open to the old
//! last-writer-wins behaviour (owner decision O4); the lock protects
//! availability and integrity between the user's own installs, not
//! confidentiality. A claim accepted that way takes the lock on a later
//! refresh once Redis answers.
//!
//! `[features.e2ee] claim_lock = false` is the emergency switch: no lock is
//! written or read, every verified claim is accepted, and acks and drains
//! follow the device row's binding alone.
//!
//! The key format and the scripts live in
//! `revolt_database::e2ee_claim_lock`, shared with delta's split
//! publication, which releases the old device's lock.

use std::{
    future::Future,
    time::{Duration, Instant},
};

use revolt_database::e2ee_claim_lock::{self as shared, session_may_act};
pub use revolt_database::e2ee_claim_lock::{
    holder_session, lock_key, lock_value, Acquire, LockError, Refresh,
};

/// How long the lock outlives the socket's idle timeout. A connection that
/// dies without releasing (a crashed node) frees its device this long after
/// it would have been dropped as silent.
pub const CLAIM_LOCK_GRACE: Duration = Duration::from_secs(30);

/// Least time between two refreshes driven by inbound frames
pub const CLAIM_LOCK_REFRESH_INTERVAL: Duration = Duration::from_secs(15);

/// `reason` of a claim refused because another session holds the lock
pub const REASON_HELD_ELSEWHERE: &str = "held_elsewhere";

/// `reason` of a claim refused because the device was removed (plan D8)
pub const REASON_REMOVED: &str = "removed";

/// Lock TTL for a socket dropped after `idle_timeout` of silence
pub fn claim_lock_ttl(idle_timeout: Duration) -> Duration {
    idle_timeout + CLAIM_LOCK_GRACE
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

    /// Set `key` to `value` with a fresh `ttl` iff its holder's session is
    /// `session_id`; an absent `key` is reported, not recreated
    fn refresh(
        &self,
        key: &str,
        value: &str,
        session_id: &str,
        ttl: Duration,
    ) -> impl Future<Output = Result<Refresh, LockError>> + Send;

    /// Delete `key` iff it still holds `value`; whether it did
    fn release(
        &self,
        key: &str,
        value: &str,
    ) -> impl Future<Output = Result<bool, LockError>> + Send;

    /// The current lock value, if any
    fn holder(&self, key: &str) -> impl Future<Output = Result<Option<String>, LockError>> + Send;
}

/// The lock in the shared Redis that presence and slowmode already use
#[derive(Clone, Copy, Debug, Default)]
pub struct RedisClaimLock;

impl ClaimLockStore for RedisClaimLock {
    async fn acquire(
        &self,
        key: &str,
        value: &str,
        session_id: &str,
        ttl: Duration,
    ) -> Result<Acquire, LockError> {
        shared::acquire(key, value, session_id, ttl).await
    }

    async fn refresh(
        &self,
        key: &str,
        value: &str,
        session_id: &str,
        ttl: Duration,
    ) -> Result<Refresh, LockError> {
        shared::refresh(key, value, session_id, ttl).await
    }

    async fn release(&self, key: &str, value: &str) -> Result<bool, LockError> {
        shared::release(key, value).await
    }

    async fn holder(&self, key: &str) -> Result<Option<String>, LockError> {
        shared::holder(key).await
    }
}

/// Verdict on a claim whose proof already verified
#[derive(Debug, PartialEq, Eq)]
pub enum ClaimDecision {
    /// This connection holds the lock
    Accepted,
    /// Redis could not decide; accepted without a lock (owner decision O4).
    /// The next refresh tries to take it again
    FailedOpen,
    /// The lock is switched off (`[features.e2ee] claim_lock = false`);
    /// accepted, nothing read or written
    LockOff,
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

/// An accepted claim whose acquire failed open, to be taken on a later
/// refresh
#[derive(Debug)]
struct Retry {
    device_id: String,
    last_attempt: Instant,
}

/// One connection's side of the lock. Dropping it releases whatever it
/// still holds, so every exit of the connection worker releases.
pub struct ConnectionClaim<S: ClaimLockStore> {
    store: S,
    user_id: String,
    session_id: String,
    value: String,
    ttl: Duration,
    /// `[features.e2ee] claim_lock`; off, the store is never touched
    lock_enabled: bool,
    held: Option<Held>,
    retry: Option<Retry>,
}

impl<S: ClaimLockStore> ConnectionClaim<S> {
    /// A connection of `session_id` with a fresh random connection id.
    /// With `lock_enabled` false (the kill switch) it neither writes nor
    /// reads the lock.
    pub fn new(
        store: S,
        user_id: &str,
        session_id: &str,
        ttl: Duration,
        lock_enabled: bool,
    ) -> Self {
        let conn_id = format!("{:016x}", rand::random::<u64>());
        Self::with_conn_id(store, user_id, session_id, &conn_id, ttl).lock_enabled(lock_enabled)
    }

    pub(crate) fn lock_enabled(mut self, enabled: bool) -> Self {
        self.lock_enabled = enabled;
        self
    }

    pub(crate) fn with_conn_id(
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
            lock_enabled: true,
            held: None,
            retry: None,
        }
    }

    /// Take the lock on `device_id` for a claim whose proof VERIFIED (never
    /// before: a keyless token must learn nothing about who holds it). A
    /// lock this connection holds on another device is released first.
    pub async fn acquire(&mut self, device_id: &str, now: Instant) -> ClaimDecision {
        if !self.lock_enabled {
            return ClaimDecision::LockOff;
        }

        // A new claim replaces any pending retry
        self.retry = None;
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
                // Taken on a later refresh once Redis answers, so the
                // device does not stay lockless for the connection's life
                if self.held.is_none() {
                    self.retry = Some(Retry {
                        device_id: device_id.to_string(),
                        last_attempt: now,
                    });
                }
                ClaimDecision::FailedOpen
            }
        }
    }

    /// Refresh the held lock if the last refresh is at least
    /// [`CLAIM_LOCK_REFRESH_INTERVAL`] old (driven by inbound frames)
    pub async fn refresh_if_due<F, Fut>(&mut self, now: Instant, bound_session: F)
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        let due = self.held.as_ref().is_some_and(|held| {
            now.saturating_duration_since(held.last_refresh) >= CLAIM_LOCK_REFRESH_INTERVAL
        }) || self.retry.as_ref().is_some_and(|retry| {
            now.saturating_duration_since(retry.last_attempt) >= CLAIM_LOCK_REFRESH_INTERVAL
        });
        if due {
            self.refresh(now, bound_session).await;
        }
    }

    /// Refresh the held lock now (the ping tick), compare-and-set on the
    /// SESSION:
    /// - our session holds it, on this connection or on a sibling that took
    ///   it over: it holds this connection's value again, with a fresh TTL;
    /// - another session holds it: let go, never taken back;
    /// - absent (a sibling of this session took it over and then closed,
    ///   or it expired): taken again only while `bound_session(device)`
    ///   (the device row's `last_session_id`, awaited only then) is still
    ///   this session. A split publication unbinds the old device and
    ///   deletes its lock on purpose, and must not see it come back.
    ///
    /// Holding nothing after a claim that failed open, it tries the acquire
    /// again, under the same binding condition.
    pub async fn refresh<F, Fut>(&mut self, now: Instant, bound_session: F)
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        let Some(held) = self.held.as_mut() else {
            self.retry_acquire(now, bound_session).await;
            return;
        };

        // Stamped even on an error, so an outage is not retried per frame
        held.last_refresh = now;
        let key = held.key.clone();
        let device_id = held.device_id.clone();

        let outcome = self
            .store
            .refresh(&key, &self.value, &self.session_id, self.ttl)
            .await;
        match outcome {
            Ok(Refresh::Extended) => {}
            Ok(Refresh::HeldElsewhere) => self.let_go(&device_id, "held by another session"),
            Ok(Refresh::Absent) => {
                let bound = bound_session(device_id.clone()).await;
                if bound.as_deref() != Some(self.session_id.as_str()) {
                    self.let_go(&device_id, "absent and no longer bound to this session");
                    return;
                }

                match self
                    .store
                    .acquire(&key, &self.value, &self.session_id, self.ttl)
                    .await
                {
                    Ok(Acquire::Acquired) => {}
                    Ok(Acquire::HeldBy(_)) => self.let_go(&device_id, "taken by another session"),
                    Err(err) => warn!(
                        "E2EE claim lock re-take failed: user={} device={} session={}: {}",
                        self.user_id, device_id, self.session_id, err.0
                    ),
                }
            }
            Err(err) => warn!(
                "E2EE claim lock refresh failed: user={} device={} session={}: {}",
                self.user_id, device_id, self.session_id, err.0
            ),
        }
    }

    /// The acquire of a claim that failed open, again: taken if the lock is
    /// free (or our session's) and the device is still bound to this
    /// session; given up once another session holds it or the binding
    /// moved; kept for the next refresh while Redis still errors
    async fn retry_acquire<F, Fut>(&mut self, now: Instant, bound_session: F)
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Option<String>>,
    {
        let Some(retry) = self.retry.as_mut() else {
            return;
        };
        retry.last_attempt = now;
        let device_id = retry.device_id.clone();

        let bound = bound_session(device_id.clone()).await;
        if bound.as_deref() != Some(self.session_id.as_str()) {
            self.retry = None;
            debug!(
                "E2EE claim lock retry dropped (no longer bound to this session): user={} device={} session={}",
                self.user_id, device_id, self.session_id
            );
            return;
        }

        let key = lock_key(&self.user_id, &device_id);
        match self
            .store
            .acquire(&key, &self.value, &self.session_id, self.ttl)
            .await
        {
            Ok(Acquire::Acquired) => {
                self.retry = None;
                info!(
                    "E2EE claim lock taken after failing open: user={} device={} session={}",
                    self.user_id, device_id, self.session_id
                );
                self.held = Some(Held {
                    device_id,
                    key,
                    last_refresh: now,
                });
            }
            Ok(Acquire::HeldBy(value)) => {
                self.retry = None;
                info!(
                    "E2EE claim lock retry found it held: user={} device={} holder_session={} session={}",
                    self.user_id,
                    device_id,
                    holder_session(&value),
                    self.session_id
                );
            }
            Err(err) => warn!(
                "E2EE claim lock still unavailable: user={} device={} session={}: {}",
                self.user_id, device_id, self.session_id, err.0
            ),
        }
    }

    /// Stop holding the lock without touching it
    fn let_go(&mut self, device_id: &str, why: &str) {
        debug!(
            "E2EE claim lock no longer ours ({}): user={} device={} session={}",
            why, self.user_id, device_id, self.session_id
        );
        self.held = None;
    }

    /// Release the held lock (compare-and-delete); a pending retry is
    /// dropped
    pub async fn release(&mut self) {
        self.retry = None;
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
    ///
    /// With the lock switched off it is not read at all and the binding
    /// alone decides: a lock left in Redis from before the switch grants
    /// nothing.
    pub async fn may_act<F>(&self, device_id: &str, bound_session: F) -> bool
    where
        F: Future<Output = Option<String>>,
    {
        if !self.lock_enabled {
            return session_may_act(Ok(None), &self.session_id, bound_session).await;
        }

        let lock = self.store.holder(&lock_key(&self.user_id, device_id)).await;
        if let Err(err) = &lock {
            debug!(
                "E2EE claim lock unreadable, checking the device binding: user={} device={}: {}",
                self.user_id, device_id, err.0
            );
        }

        session_may_act(lock, &self.session_id, bound_session).await
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

/// In-memory lock with the scripts' semantics and a clock the test moves;
/// shared with the worker tests in `websocket.rs`
#[cfg(test)]
pub(crate) mod fake {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use super::{holder_session, Acquire, ClaimLockStore, LockError, Refresh};

    #[derive(Clone)]
    pub(crate) struct FakeLock(pub(crate) Arc<Mutex<FakeState>>);

    pub(crate) struct FakeState {
        pub(crate) now: Instant,
        pub(crate) entries: HashMap<String, (String, Instant)>,
        pub(crate) failing: bool,
        pub(crate) refreshes: usize,
        pub(crate) acquires: usize,
        /// Every store call, failing ones included
        pub(crate) calls: usize,
    }

    impl FakeLock {
        pub(crate) fn new() -> Self {
            FakeLock(Arc::new(Mutex::new(FakeState {
                now: Instant::now(),
                entries: HashMap::new(),
                failing: false,
                refreshes: 0,
                acquires: 0,
                calls: 0,
            })))
        }

        /// How many store calls (acquire, refresh, release, holder) were made
        pub(crate) fn calls(&self) -> usize {
            self.0.lock().unwrap().calls
        }

        pub(crate) fn now(&self) -> Instant {
            self.0.lock().unwrap().now
        }

        pub(crate) fn advance(&self, by: Duration) {
            self.0.lock().unwrap().now += by;
        }

        pub(crate) fn fail(&self, failing: bool) {
            self.0.lock().unwrap().failing = failing;
        }

        pub(crate) fn refreshes(&self) -> usize {
            self.0.lock().unwrap().refreshes
        }

        /// How many acquire calls reached the store, failing ones included
        pub(crate) fn acquires(&self) -> usize {
            self.0.lock().unwrap().acquires
        }

        pub(crate) fn get(&self, key: &str) -> Option<String> {
            let mut state = self.0.lock().unwrap();
            state.live(key)
        }

        /// Set `key` to `value` with `ttl`, as another node would
        pub(crate) fn put(&self, key: &str, value: &str, ttl: Duration) {
            let mut state = self.0.lock().unwrap();
            let expires = state.now + ttl;
            state.entries.insert(key.to_string(), (value.to_string(), expires));
        }

        pub(crate) fn remove(&self, key: &str) {
            self.0.lock().unwrap().entries.remove(key);
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
            state.acquires += 1;
            state.calls += 1;
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

        async fn refresh(
            &self,
            key: &str,
            value: &str,
            session_id: &str,
            ttl: Duration,
        ) -> Result<Refresh, LockError> {
            let mut state = self.0.lock().unwrap();
            state.calls += 1;
            state.check()?;
            state.refreshes += 1;
            match state.live(key) {
                None => Ok(Refresh::Absent),
                Some(current) if holder_session(&current) != session_id => {
                    Ok(Refresh::HeldElsewhere)
                }
                Some(_) => {
                    let expires = state.now + ttl;
                    state.entries.insert(key.to_string(), (value.to_string(), expires));
                    Ok(Refresh::Extended)
                }
            }
        }

        async fn release(&self, key: &str, value: &str) -> Result<bool, LockError> {
            let mut state = self.0.lock().unwrap();
            state.calls += 1;
            state.check()?;
            if state.live(key).as_deref() == Some(value) {
                state.entries.remove(key);
                return Ok(true);
            }
            Ok(false)
        }

        async fn holder(&self, key: &str) -> Result<Option<String>, LockError> {
            let mut state = self.0.lock().unwrap();
            state.calls += 1;
            state.check()?;
            Ok(state.live(key))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use redis_kiss::{get_connection, AsyncCommands};

    use super::fake::FakeLock;
    use super::*;

    const TTL: Duration = Duration::from_secs(150);

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

    /// The refresh's device-binding lookup: every device bound to `session`
    fn bound_to(session: Option<&str>) -> impl FnOnce(String) -> std::future::Ready<Option<String>> {
        let session = session.map(str::to_string);
        move |_device| std::future::ready(session)
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
        first.refresh(lock.now(), bound_to(Some("S1"))).await;
        lock.advance(Duration::from_secs(2));
        assert!(!other.acquire("D", lock.now()).await.is_accepted());
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));
    }

    /// Another SESSION took the device (after this connection's lock
    /// expired): a refresh neither steals it back nor extends it
    #[tokio::test]
    async fn d4_refresh_after_a_takeover_does_not_steal() {
        let lock = FakeLock::new();
        let mut old = conn(&lock, "S1", "c1");
        let mut new = conn(&lock, "S2", "c2");

        assert!(old.acquire("D", lock.now()).await.is_accepted());
        lock.advance(TTL);
        assert!(new.acquire("D", lock.now()).await.is_accepted());

        lock.advance(Duration::from_secs(20));
        // Even while the row still names the old session
        old.refresh(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S2:c2"));

        // Nor did it extend the successor's TTL, which still runs from the
        // takeover
        lock.advance(TTL - Duration::from_secs(20));
        assert_eq!(lock.get(&key("D")), None);

        // Having let go, the old connection stops refreshing
        let before = lock.refreshes();
        old.refresh(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.refreshes(), before);
    }

    /// Audit MINOR-6a: a sibling connection of the SAME session took the
    /// lock over. While it lives, our refresh re-asserts our value; once it
    /// closed and released, our refresh takes the lock again (the device is
    /// still bound to our session), so no other session can slip in
    #[tokio::test]
    async fn d4_refresh_reasserts_over_a_sibling_of_the_same_session() {
        let lock = FakeLock::new();
        let mut old = conn(&lock, "S1", "c1");
        let mut sibling = conn(&lock, "S1", "c2");
        let mut other = conn(&lock, "S2", "c3");

        assert!(old.acquire("D", lock.now()).await.is_accepted());
        assert!(sibling.acquire("D", lock.now()).await.is_accepted());
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c2"));

        lock.advance(Duration::from_secs(30));
        old.refresh(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"), "re-asserted");

        // The sibling's release cannot delete the value we re-asserted
        sibling.release().await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));

        // Another sibling takes it over and closes, deleting its own value
        let mut sibling = conn(&lock, "S1", "c4");
        assert!(sibling.acquire("D", lock.now()).await.is_accepted());
        sibling.release().await;
        assert_eq!(lock.get(&key("D")), None);

        // Ours is taken again
        old.refresh(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"), "re-taken");
        assert!(!other.acquire("D", lock.now()).await.is_accepted());

        // And it lasts a full TTL from that refresh
        lock.advance(TTL - Duration::from_secs(1));
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));
    }

    /// Audit MINOR-6a with MAJOR-1: an absent lock is taken again only while
    /// the device is still bound to this session. A split publication
    /// unbinds the old device (bound to `""`) and deletes its lock; the
    /// refresh must not bring it back
    #[tokio::test]
    async fn d4_refresh_does_not_retake_an_unbound_device() {
        for binding in [Some(""), Some("S2"), None] {
            let lock = FakeLock::new();
            let mut ours = conn(&lock, "S1", "c1");
            assert!(ours.acquire("D", lock.now()).await.is_accepted());
            lock.remove(&key("D"));

            let acquires = lock.acquires();
            ours.refresh(lock.now(), bound_to(binding)).await;
            assert_eq!(lock.get(&key("D")), None, "binding {binding:?}");
            assert_eq!(lock.acquires(), acquires, "binding {binding:?}");

            // Let go: later refreshes do nothing
            let refreshes = lock.refreshes();
            ours.refresh(lock.now(), bound_to(Some("S1"))).await;
            assert_eq!(lock.refreshes(), refreshes, "binding {binding:?}");
        }
    }

    #[tokio::test]
    async fn d4_inbound_refresh_is_throttled() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        assert!(first.acquire("D", lock.now()).await.is_accepted());

        lock.advance(CLAIM_LOCK_REFRESH_INTERVAL - Duration::from_secs(1));
        first.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.refreshes(), 0);

        lock.advance(Duration::from_secs(1));
        first.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.refreshes(), 1);

        first.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
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
        first.refresh(lock.now(), bound_to(Some("S1"))).await;
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

    /// Addendum A3(b): with the lock switched off a connection never touches
    /// the store: a claim another session holds is accepted, nothing is
    /// refreshed or released, and the ack gate is the device binding alone,
    /// so a lock left in Redis grants nothing
    #[tokio::test]
    async fn lock_off_never_touches_the_store() {
        let lock = FakeLock::new();
        lock.put(&key("D"), "S2:c2", TTL);
        let mut off = conn(&lock, "S1", "c1").lock_enabled(false);

        let decision = off.acquire("D", lock.now()).await;
        assert_eq!(decision, ClaimDecision::LockOff);
        assert!(decision.is_accepted());

        lock.advance(CLAIM_LOCK_REFRESH_INTERVAL);
        off.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
        off.refresh(lock.now(), bound_to(Some("S1"))).await;

        // A stale lock naming this session: the binding (S2) decides
        lock.put(&key("D"), "S1:c1", TTL);
        let polled = Arc::new(AtomicBool::new(false));
        assert!(!off.may_act("D", bound(Some("S2"), &polled)).await);
        assert!(polled.load(Ordering::SeqCst), "the binding was not consulted");
        assert!(off.may_act("D", bound(Some("S1"), &polled)).await);

        off.release().await;
        drop(off);
        tokio::task::yield_now().await;
        assert_eq!(lock.calls(), 0, "the switched-off connection used the store");
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));

        // The same stale lock does grant rights while the lock is on
        let on = conn(&lock, "S1", "c3");
        assert!(on.may_act("D", bound(Some("S2"), &polled)).await);
    }

    /// Addendum A3 m2: a claim whose acquire failed open takes the lock on
    /// the next refresh once Redis answers, and keeps trying while it does
    /// not
    #[tokio::test]
    async fn failed_open_acquire_is_taken_on_the_next_refresh() {
        let lock = FakeLock::new();
        let mut first = conn(&lock, "S1", "c1");
        let mut other = conn(&lock, "S2", "c2");

        lock.fail(true);
        assert_eq!(first.acquire("D", lock.now()).await, ClaimDecision::FailedOpen);

        // Still down at the first tick: nothing taken, the retry is kept
        first.refresh(lock.now(), bound_to(Some("S1"))).await;
        lock.fail(false);
        assert_eq!(lock.get(&key("D")), None);

        // Inbound frames retry at most once per refresh interval
        let acquires = lock.acquires();
        first.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.acquires(), acquires, "retried before the interval");
        lock.advance(CLAIM_LOCK_REFRESH_INTERVAL);
        first.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"), "not taken");
        assert!(!other.acquire("D", lock.now()).await.is_accepted());

        // Held now, so it is refreshed like any held lock
        lock.advance(TTL - Duration::from_secs(1));
        first.refresh(lock.now(), bound_to(Some("S1"))).await;
        lock.advance(Duration::from_secs(2));
        assert_eq!(lock.get(&key("D")).as_deref(), Some("S1:c1"));

        // And the ping tick alone retakes it too
        let mut second = conn(&lock, "S3", "c3");
        lock.fail(true);
        assert_eq!(second.acquire("E", lock.now()).await, ClaimDecision::FailedOpen);
        lock.fail(false);
        second.refresh(lock.now(), bound_to(Some("S3"))).await;
        assert_eq!(lock.get(&key("E")).as_deref(), Some("S3:c3"));
    }

    /// The retry gives up, writing nothing, once another session holds the
    /// lock or the device is no longer bound to this session
    #[tokio::test]
    async fn failed_open_retry_gives_up_on_another_holder_or_binding() {
        for (case, binding) in [("held", Some("S1")), ("unbound", Some("")), ("moved", Some("S2"))] {
            let lock = FakeLock::new();
            let mut ours = conn(&lock, "S1", "c1");
            lock.fail(true);
            assert_eq!(ours.acquire("D", lock.now()).await, ClaimDecision::FailedOpen);
            lock.fail(false);
            if case == "held" {
                lock.put(&key("D"), "S2:c2", TTL);
            }

            ours.refresh(lock.now(), bound_to(binding)).await;
            let expected = (case == "held").then(|| "S2:c2".to_string());
            assert_eq!(lock.get(&key("D")), expected, "{case}");

            // Given up: later refreshes try nothing
            let calls = lock.calls();
            lock.remove(&key("D"));
            lock.advance(CLAIM_LOCK_REFRESH_INTERVAL);
            ours.refresh(lock.now(), bound_to(Some("S1"))).await;
            ours.refresh_if_due(lock.now(), bound_to(Some("S1"))).await;
            assert_eq!(lock.calls(), calls, "{case}: retried after giving up");
            assert_eq!(lock.get(&key("D")), None, "{case}");
        }
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

            // Another session's refresh neither steals nor extends
            let _: () = conn.pexpire(&key, 5_000).await.expect("pexpire");
            assert_eq!(
                redis.refresh(&key, "S2:c2", "S2", ttl).await.expect("refresh"),
                Refresh::HeldElsewhere
            );
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), Some("S1:c4"));
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 0 && pttl <= 5_000, "a stale refresh extended the TTL: {pttl}");

            // A sibling connection of the holder's session re-asserts its own
            // value with a fresh TTL (audit MINOR-6a)
            assert_eq!(
                redis.refresh(&key, "S1:c1", "S1", ttl).await.expect("refresh"),
                Refresh::Extended
            );
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), Some("S1:c1"));
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 5_000 && pttl <= ttl.as_millis() as i64, "pttl {pttl}");

            // The holder's refresh extends
            let _: () = conn.pexpire(&key, 5_000).await.expect("pexpire");
            assert_eq!(
                redis.refresh(&key, "S1:c1", "S1", ttl).await.expect("refresh"),
                Refresh::Extended
            );
            let pttl: i64 = conn.pttl(&key).await.expect("pttl");
            assert!(pttl > 5_000 && pttl <= ttl.as_millis() as i64, "pttl {pttl}");

            // A stale release deletes nothing; the holder's deletes
            assert!(!redis.release(&key, "S1:c4").await.expect("release"));
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), Some("S1:c1"));
            assert!(redis.release(&key, "S1:c1").await.expect("release"));
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), None);

            // Absent: refresh reports it and creates nothing, release is a
            // no-op, acquire takes it
            assert_eq!(
                redis.refresh(&key, "S1:c1", "S1", ttl).await.expect("refresh"),
                Refresh::Absent
            );
            assert_eq!(redis.holder(&key).await.expect("holder").as_deref(), None);
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
