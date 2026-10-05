//! Volume cap for UnifiedPush sends. Endpoints are client-supplied, so
//! without one an account with many sessions could make us POST at a third
//! party, or at ntfy.sh until it bans our IP, as fast as messages arrive.
//!
//! Every send needs a token from two buckets: one per destination key and
//! one per (user, destination key). The caller normalizes the key; it is
//! opaque here. Accepted residual: about ten accounts sending at the
//! per-user rate match the per-destination refill, so together they can
//! starve one destination for everyone until moderation acts. The real
//! bound is a per-user UnifiedPush subscription cap in delta.

use std::{
    collections::HashMap,
    hash::Hash,
    net::IpAddr,
    sync::{Mutex, MutexGuard, PoisonError},
    time::Instant,
};

// Untuned starting values, used by `UpLimiter::new`. ntfy.sh, the usual
// distributor, gives each visitor IP a burst of 60 refilled at one request
// per 5 s, but it can charge `up*` topics to the subscriber instead, so
// these are abuse caps rather than a promise to stay under its bucket.

/// Burst per destination key. Every user's sends to one destination share
/// it, so it is the backstop.
pub const IP_BURST: f64 = 300.0;

/// Tokens refilled per second per destination key.
pub const IP_REFILL_PER_SEC: f64 = 30.0;

/// Burst per (user, destination key). It counts pushes, not messages, so it
/// leaves room for a user with several UnifiedPush devices in a busy group.
pub const USER_BURST: f64 = 60.0;

/// Tokens refilled per second per (user, destination key).
pub const USER_REFILL_PER_SEC: f64 = 3.0;

/// How long a 429 from the push server holds back that user's sends to that
/// destination, in seconds of refill.
pub const USER_429_COOLDOWN_SECS: f64 = 30.0;

/// Most entries each bucket map holds.
pub const MAX_KEYS: usize = 4096;

/// The bucket that refused a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    /// The per-destination bucket every user shares.
    Ip,
    /// The (user, destination) bucket.
    User,
}

/// Whether a send may go out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    Allowed,
    /// `first` is true on the first denial since `bucket` last held a whole
    /// token, so the caller can log once per episode.
    Denied {
        first: bool,
        bucket: Bucket,
    },
}

#[derive(Clone, Copy)]
struct Limits {
    burst: f64,
    refill_per_sec: f64,
}

struct TokenBucket {
    tokens: f64,
    /// Latest time seen; refill counts from here.
    last: Instant,
    /// The call counter when this bucket was last used, for LRU eviction.
    touched: u64,
    /// Whether this bucket has denied since it last held a whole token.
    denied: bool,
}

impl TokenBucket {
    fn full(limits: Limits, now: Instant) -> Self {
        TokenBucket {
            tokens: limits.burst,
            last: now,
            touched: 0,
            denied: false,
        }
    }

    /// Add what was earned since `last`, capped at the burst. Deliveries run
    /// as separate tasks, so `now` can be earlier than `last`: that adds
    /// nothing and keeps `last`, so no interval is counted twice.
    fn refill(&mut self, limits: Limits, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * limits.refill_per_sec).min(limits.burst);
        self.last = self.last.max(now);

        if self.tokens >= 1.0 {
            self.denied = false;
        }
    }

    fn is_full(&self, limits: Limits) -> bool {
        self.tokens >= limits.burst
    }

    /// Record a denial. True if it is the first of this empty episode.
    fn deny(&mut self) -> bool {
        let first = !self.denied;
        self.denied = true;
        first
    }
}

struct State {
    ip: HashMap<IpAddr, TokenBucket>,
    user: HashMap<(String, IpAddr), TokenBucket>,
    /// Bumped on every call, stamped into `TokenBucket::touched`.
    calls: u64,
}

/// Per-destination and per-(user, destination) token buckets for
/// UnifiedPush sends. One instance is shared by every delivery.
pub struct UpLimiter {
    ip: Limits,
    user: Limits,
    max_keys: usize,
    state: Mutex<State>,
}

impl UpLimiter {
    pub fn new() -> Self {
        Self::with_limits(
            IP_BURST,
            IP_REFILL_PER_SEC,
            USER_BURST,
            USER_REFILL_PER_SEC,
            MAX_KEYS,
        )
    }

    /// A limiter with explicit limits. Each map keeps at least one entry,
    /// so a `max_keys` of 0 acts as 1.
    pub fn with_limits(
        ip_burst: f64,
        ip_refill_per_sec: f64,
        user_burst: f64,
        user_refill_per_sec: f64,
        max_keys: usize,
    ) -> Self {
        UpLimiter {
            ip: Limits {
                burst: ip_burst,
                refill_per_sec: ip_refill_per_sec,
            },
            user: Limits {
                burst: user_burst,
                refill_per_sec: user_refill_per_sec,
            },
            max_keys: max_keys.max(1),
            state: Mutex::new(State {
                ip: HashMap::new(),
                user: HashMap::new(),
                calls: 0,
            }),
        }
    }

    /// Take one token from both buckets for a send by `user_id` to `key`,
    /// or take nothing and say which bucket is empty. The destination is
    /// checked first, so an exhausted destination is never blamed on
    /// whichever user happened to hit it.
    pub fn admit(&self, user_id: &str, key: IpAddr, now: Instant) -> Admit {
        let mut state = self.lock();
        let State { ip, user, calls } = &mut *state;
        *calls = calls.wrapping_add(1);

        let ip_bucket = bucket_for(ip, key, self.ip, self.max_keys, now, *calls);
        let user_bucket = bucket_for(
            user,
            (user_id.to_owned(), key),
            self.user,
            self.max_keys,
            now,
            *calls,
        );

        if ip_bucket.tokens < 1.0 {
            return Admit::Denied {
                first: ip_bucket.deny(),
                bucket: Bucket::Ip,
            };
        }

        if user_bucket.tokens < 1.0 {
            return Admit::Denied {
                first: user_bucket.deny(),
                bucket: Bucket::User,
            };
        }

        ip_bucket.tokens -= 1.0;
        user_bucket.tokens -= 1.0;
        Admit::Allowed
    }

    /// Hold back `user_id`'s sends to `key` for about
    /// `USER_429_COOLDOWN_SECS` after a 429. The tokens are set, not
    /// reduced, so repeated 429s cannot push the bucket further down. The
    /// destination bucket is left alone: ntfy can answer 429 per subscriber
    /// on `up*` topics, and one user's 429 must not stall everyone else.
    pub fn drain_user(&self, user_id: &str, key: IpAddr, now: Instant) {
        let mut state = self.lock();
        let State { user, calls, .. } = &mut *state;
        *calls = calls.wrapping_add(1);

        let bucket = bucket_for(
            user,
            (user_id.to_owned(), key),
            self.user,
            self.max_keys,
            now,
            *calls,
        );

        bucket.tokens = -(USER_429_COOLDOWN_SECS * self.user.refill_per_sec);
    }

    /// A panic elsewhere while holding the lock must not stop push, and the
    /// maps stay usable whatever state it left them in.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for UpLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// The bucket for `key`, refilled to `now` and stamped as touched. A new key
/// starts full and is never refused for lack of room.
fn bucket_for<K: Eq + Hash + Clone>(
    map: &mut HashMap<K, TokenBucket>,
    key: K,
    limits: Limits,
    max_keys: usize,
    now: Instant,
    calls: u64,
) -> &mut TokenBucket {
    if !map.contains_key(&key) {
        make_room(map, limits, max_keys, now);
    }

    let bucket = map
        .entry(key)
        .or_insert_with(|| TokenBucket::full(limits, now));

    bucket.refill(limits, now);
    bucket.touched = calls;
    bucket
}

/// Make room for one more entry in a full map. Buckets that are full after
/// refilling to `now` go first, since they would come back identical; then
/// the least recently touched ones.
fn make_room<K: Eq + Hash + Clone>(
    map: &mut HashMap<K, TokenBucket>,
    limits: Limits,
    max_keys: usize,
    now: Instant,
) {
    if map.len() < max_keys {
        return;
    }

    map.retain(|_, bucket| {
        bucket.refill(limits, now);
        !bucket.is_full(limits)
    });

    while map.len() >= max_keys {
        let Some(oldest) = map
            .iter()
            .min_by_key(|(_, bucket)| bucket.touched)
            .map(|(key, _)| key.clone())
        else {
            break;
        };

        map.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{net::Ipv4Addr, time::Duration};

    const ALLOWED: Admit = Admit::Allowed;

    fn denied(first: bool, bucket: Bucket) -> Admit {
        Admit::Denied { first, bucket }
    }

    /// A destination key in TEST-NET-3.
    fn key(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, n))
    }

    fn after(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    fn ip_tokens(limiter: &UpLimiter, key: IpAddr) -> Option<f64> {
        limiter.lock().ip.get(&key).map(|bucket| bucket.tokens)
    }

    fn user_tokens(limiter: &UpLimiter, user: &str, key: IpAddr) -> Option<f64> {
        let state = limiter.lock();
        state
            .user
            .get(&(user.to_string(), key))
            .map(|bucket| bucket.tokens)
    }

    fn map_sizes(limiter: &UpLimiter) -> (usize, usize) {
        let state = limiter.lock();
        (state.ip.len(), state.user.len())
    }

    fn ip_keys(limiter: &UpLimiter) -> Vec<IpAddr> {
        let mut keys: Vec<_> = limiter.lock().ip.keys().copied().collect();
        keys.sort();
        keys
    }

    fn user_keys(limiter: &UpLimiter) -> Vec<(String, IpAddr)> {
        let mut keys: Vec<_> = limiter.lock().user.keys().cloned().collect();
        keys.sort();
        keys
    }

    fn user_key(user: &str, n: u8) -> (String, IpAddr) {
        (user.to_string(), key(n))
    }

    #[test]
    fn burst_admits_then_denies() {
        let limiter = UpLimiter::with_limits(100.0, 0.0, 3.0, 0.0, 16);
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));
    }

    #[test]
    fn partial_refill_after_elapsed() {
        let limiter = UpLimiter::with_limits(100.0, 0.0, 10.0, 2.0, 16);
        let t0 = Instant::now();

        for _ in 0..10 {
            assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));

        // 1.5 s at 2 per second earns 3 tokens.
        let t1 = after(t0, 1500);
        for _ in 0..3 {
            assert_eq!(limiter.admit("a", key(1), t1), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t1), denied(true, Bucket::User));
    }

    #[test]
    fn tokens_cap_at_burst() {
        let limiter = UpLimiter::with_limits(100.0, 0.0, 3.0, 1.0, 16);
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        }

        // 100 s of refill still leaves only the burst.
        let t1 = after(t0, 100_000);
        for _ in 0..3 {
            assert_eq!(limiter.admit("a", key(1), t1), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t1), denied(true, Bucket::User));
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));
    }

    #[test]
    fn destination_keys_are_independent() {
        let limiter = UpLimiter::with_limits(2.0, 0.0, 100.0, 0.0, 16);
        let t0 = Instant::now();

        for n in [1, 2] {
            for _ in 0..2 {
                assert_eq!(limiter.admit("a", key(n), t0), ALLOWED, "key {n}");
            }
            assert_eq!(
                limiter.admit("a", key(n), t0),
                denied(true, Bucket::Ip),
                "key {n}"
            );
        }
    }

    #[test]
    fn user_bucket_caps_one_user_only() {
        let limiter = UpLimiter::with_limits(100.0, 0.0, 3.0, 0.0, 16);
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));

        // Another user sending to the same destination is unaffected.
        for _ in 0..3 {
            assert_eq!(limiter.admit("b", key(1), t0), ALLOWED);
        }
    }

    #[test]
    fn destination_bucket_caps_across_users() {
        let limiter = UpLimiter::with_limits(5.0, 0.0, 2.0, 0.0, 64);
        let t0 = Instant::now();

        for n in 0..5 {
            assert_eq!(limiter.admit(&format!("u{n}"), key(1), t0), ALLOWED);
        }

        // Every later user still has tokens, so the destination is blamed.
        for n in 5..10 {
            assert_eq!(
                limiter.admit(&format!("u{n}"), key(1), t0),
                denied(n == 5, Bucket::Ip),
                "user u{n}"
            );
        }
    }

    #[test]
    fn denial_takes_no_token() {
        let t0 = Instant::now();

        // Refused by the user bucket: the destination keeps its tokens.
        let limiter = UpLimiter::with_limits(5.0, 0.0, 1.0, 0.0, 16);
        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        assert_eq!(ip_tokens(&limiter, key(1)), Some(4.0));
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));
        assert_eq!(ip_tokens(&limiter, key(1)), Some(4.0));
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));

        // Refused by the destination bucket: no user bucket loses a token.
        let limiter = UpLimiter::with_limits(1.0, 0.0, 5.0, 0.0, 16);
        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("b", key(1), t0), denied(true, Bucket::Ip));
        assert_eq!(user_tokens(&limiter, "b", key(1)), Some(5.0));
        assert_eq!(limiter.admit("a", key(1), t0), denied(false, Bucket::Ip));
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(4.0));
        assert_eq!(ip_tokens(&limiter, key(1)), Some(0.0));
    }

    #[test]
    fn drain_user_cools_down_only_that_pair() {
        let limiter = UpLimiter::with_limits(1000.0, 0.0, 6.0, USER_REFILL_PER_SEC, 16);
        let t0 = Instant::now();

        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("b", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("a", key(2), t0), ALLOWED);
        let destination = ip_tokens(&limiter, key(1));

        limiter.drain_user("a", key(1), t0);

        assert_eq!(
            user_tokens(&limiter, "a", key(1)),
            Some(-(USER_429_COOLDOWN_SECS * USER_REFILL_PER_SEC))
        );
        assert_eq!(ip_tokens(&limiter, key(1)), destination);
        assert_eq!(user_tokens(&limiter, "b", key(1)), Some(5.0));
        assert_eq!(user_tokens(&limiter, "a", key(2)), Some(5.0));

        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));
        assert_eq!(limiter.admit("b", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("a", key(2), t0), ALLOWED);

        // Still held back just before the cooldown ends...
        let cooldown = Duration::from_secs_f64(USER_429_COOLDOWN_SECS);
        let almost = t0 + cooldown - Duration::from_millis(1);
        assert_eq!(
            limiter.admit("a", key(1), almost),
            denied(false, Bucket::User)
        );

        // ...and admitted once it has passed and a token has been earned.
        let later = t0 + cooldown + Duration::from_secs(1);
        assert_eq!(limiter.admit("a", key(1), later), ALLOWED);
    }

    #[test]
    fn drain_user_with_no_refill_still_denies() {
        let limiter = UpLimiter::with_limits(5.0, 0.0, 5.0, 0.0, 16);
        let t0 = Instant::now();

        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        limiter.drain_user("a", key(1), t0);

        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));
        assert_eq!(
            limiter.admit("a", key(1), after(t0, 3_600_000)),
            denied(true, Bucket::User)
        );
        assert_eq!(limiter.admit("b", key(1), t0), ALLOWED);
    }

    #[test]
    fn drain_user_sets_rather_than_subtracts() {
        let limiter = UpLimiter::with_limits(5.0, 0.0, 5.0, 1.0, 16);
        let t0 = Instant::now();
        let drained = Some(-USER_429_COOLDOWN_SECS);

        // An unknown pair gets an entry; the destination map is not touched.
        limiter.drain_user("a", key(1), t0);
        assert_eq!(user_tokens(&limiter, "a", key(1)), drained);
        assert_eq!(ip_tokens(&limiter, key(1)), None);

        limiter.drain_user("a", key(1), t0);
        assert_eq!(user_tokens(&limiter, "a", key(1)), drained);
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));
    }

    #[test]
    fn first_is_tracked_per_bucket() {
        let t0 = Instant::now();
        let t1 = after(t0, 1000);

        // True once per empty episode, and again after a refill.
        let limiter = UpLimiter::with_limits(100.0, 0.0, 1.0, 1.0, 16);
        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));
        assert_eq!(limiter.admit("a", key(1), t0), denied(false, Bucket::User));
        assert_eq!(limiter.admit("a", key(1), t1), ALLOWED);
        assert_eq!(limiter.admit("a", key(1), t1), denied(true, Bucket::User));

        // The destination bucket keeps its own flag.
        let limiter = UpLimiter::with_limits(2.0, 1.0, 1.0, 1.0, 16);
        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));
        assert_eq!(limiter.admit("b", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("c", key(1), t0), denied(true, Bucket::Ip));
        assert_eq!(limiter.admit("d", key(1), t0), denied(false, Bucket::Ip));
        // Both empty: the destination is reported.
        assert_eq!(limiter.admit("a", key(1), t0), denied(false, Bucket::Ip));
        assert_eq!(limiter.admit("c", key(1), t1), ALLOWED);
        assert_eq!(limiter.admit("d", key(1), t1), denied(true, Bucket::Ip));

        // A denial reported as the destination's leaves the user's flag armed.
        let limiter = UpLimiter::with_limits(1.0, 1.0, 1.0, 0.0, 16);
        assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::Ip));
        assert_eq!(limiter.admit("a", key(1), t1), denied(true, Bucket::User));
    }

    #[test]
    fn out_of_order_now_neither_panics_nor_double_refills() {
        let limiter = UpLimiter::with_limits(100.0, 0.0, 2.0, 1.0, 16);
        let t0 = Instant::now();
        let t10 = after(t0, 10_000);

        for _ in 0..2 {
            assert_eq!(limiter.admit("a", key(1), t10), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t10), denied(true, Bucket::User));

        // A delivery stamped before the bucket's last update earns nothing.
        assert_eq!(limiter.admit("a", key(1), t0), denied(false, Bucket::User));
        limiter.drain_user("b", key(1), t10);
        limiter.drain_user("b", key(1), t0);
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));

        // Back in order, only time after t10 counts, and only once.
        let t10_5 = after(t0, 10_500);
        assert_eq!(
            limiter.admit("a", key(1), t10_5),
            denied(false, Bucket::User)
        );
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.5));
        assert_eq!(limiter.admit("a", key(1), after(t0, 11_000)), ALLOWED);
        assert_eq!(
            limiter.admit("a", key(1), after(t0, 11_000)),
            denied(true, Bucket::User)
        );

        // The drained pair's cooldown runs from t10, not from t0.
        assert_eq!(
            limiter.admit("b", key(1), after(t0, 39_000)),
            denied(true, Bucket::User)
        );
    }

    #[test]
    fn key_flood_stays_bounded() {
        let max_keys = 8;
        let t0 = Instant::now();

        // Many destinations, each from its own user.
        let limiter = UpLimiter::with_limits(2.0, 0.0, 2.0, 0.0, max_keys);
        for n in 0..1000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(n));
            // A new key is never refused for lack of room.
            assert_eq!(limiter.admit(&format!("u{n}"), ip, t0), ALLOWED, "{ip}");

            let (ips, users) = map_sizes(&limiter);
            assert!(
                ips <= max_keys && users <= max_keys,
                "{ips}/{users} at {ip}"
            );
        }

        // The buckets still count after the churn.
        for _ in 0..2 {
            assert_eq!(limiter.admit("z", key(1), t0), ALLOWED);
        }
        assert_eq!(limiter.admit("z", key(1), t0), denied(true, Bucket::Ip));

        // Many users, one destination.
        let limiter = UpLimiter::with_limits(1_000_000.0, 0.0, 2.0, 0.0, max_keys);
        for n in 0..1000 {
            assert_eq!(limiter.admit(&format!("u{n}"), key(1), t0), ALLOWED);
            assert!(map_sizes(&limiter).1 <= max_keys, "user u{n}");
        }
        assert_eq!(map_sizes(&limiter).0, 1);
    }

    #[test]
    fn idle_full_buckets_are_pruned_before_lru() {
        let limiter = UpLimiter::with_limits(2.0, 1.0, 2.0, 1.0, 3);
        let t0 = Instant::now();

        // Keys 2 and 3 are emptied first, so key 1 is the most recently
        // touched, and key 2 the least.
        for n in [2, 3] {
            for _ in 0..2 {
                assert_eq!(limiter.admit("u", key(n), t0), ALLOWED);
            }
        }
        assert_eq!(limiter.admit("u", key(1), t0), ALLOWED);

        // A second later key 1 is full again; keys 2 and 3 are not.
        assert_eq!(limiter.admit("u", key(4), after(t0, 1000)), ALLOWED);

        assert_eq!(ip_keys(&limiter), vec![key(2), key(3), key(4)]);
        assert_eq!(
            user_keys(&limiter),
            vec![user_key("u", 2), user_key("u", 3), user_key("u", 4)]
        );
    }

    #[test]
    fn least_recently_touched_is_evicted() {
        let limiter = UpLimiter::with_limits(2.0, 0.0, 2.0, 0.0, 3);
        let t0 = Instant::now();

        for n in [1, 2, 3] {
            assert_eq!(limiter.admit("u", key(n), t0), ALLOWED);
        }
        // Touch key 1 again, leaving key 2 the least recently touched.
        assert_eq!(limiter.admit("u", key(1), t0), ALLOWED);

        // Nothing refills, so nothing is idle-full and key 2 goes.
        assert_eq!(limiter.admit("u", key(4), t0), ALLOWED);
        assert_eq!(ip_keys(&limiter), vec![key(1), key(3), key(4)]);
        assert_eq!(
            user_keys(&limiter),
            vec![user_key("u", 1), user_key("u", 3), user_key("u", 4)]
        );

        // An evicted key comes back with a full allowance.
        for _ in 0..2 {
            assert_eq!(limiter.admit("u", key(2), t0), ALLOWED);
        }
        assert_eq!(map_sizes(&limiter), (3, 3));
    }

    #[test]
    fn new_and_default_use_the_constants() {
        let t0 = Instant::now();

        let limiter = UpLimiter::new();
        for _ in 0..USER_BURST as usize {
            assert_eq!(limiter.admit("a", key(1), t0), ALLOWED);
        }
        assert_eq!(limiter.admit("a", key(1), t0), denied(true, Bucket::User));

        let limiter = UpLimiter::default();
        for n in 0..IP_BURST as usize {
            assert_eq!(limiter.admit(&format!("u{n}"), key(1), t0), ALLOWED);
        }
        assert_eq!(limiter.admit("late", key(1), t0), denied(true, Bucket::Ip));

        limiter.drain_user("a", key(1), t0);
        assert_eq!(
            user_tokens(&limiter, "a", key(1)),
            Some(-(USER_429_COOLDOWN_SECS * USER_REFILL_PER_SEC))
        );
    }
}
