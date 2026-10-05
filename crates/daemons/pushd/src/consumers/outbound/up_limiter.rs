//! Volume and rejection caps for UnifiedPush sends. Endpoints are
//! client-supplied, so without them an account with many sessions could
//! make us POST at a third party, or at ntfy.sh until it bans our IP, as
//! fast as messages arrive.
//!
//! Every send needs a token from the destination's send bucket and one from
//! the (user, destination) bucket, a free in-flight slot, and a reservation
//! on the destination's rejection budget. `admit` hands out a `Ticket` that
//! holds the reservation; completing it as a rejection spends a budget
//! token. So a destination never sees more rejections from us than its
//! budget allows, however many sends are in flight. A 503 from ntfy.sh, its
//! nginx rate limit, also pauses it outright. A subscription that was
//! rejected cools down before it may send again.
//!
//! The caller normalizes the destination key. ntfy.sh is keyed by host and
//! gets its own, much lower, send rate. Accepted residuals: a few accounts
//! sending at the per-user rate can drain a destination's send bucket for
//! everyone, and sessions on dead topics can spend its rejection budget,
//! until moderation acts. The caller names the heaviest senders
//! (`top_senders`) and rejecters (`Rejected::Paused`) in its logs; the
//! alternative is a ban of our IP.

use std::{
    cmp::Ordering,
    collections::{hash_map::DefaultHasher, HashMap},
    fmt,
    hash::{Hash, Hasher},
    net::IpAddr,
    sync::{Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use tokio::sync::{futures::Notified, Notify};

// Untuned starting values, used by `UpLimits::default`. ntfy.sh documents
// its own setup as nginx `limit_req` at 45 requests a minute per client IP
// with a burst of 1000, and a fail2ban jail that bans an IP for 4 h after 10
// of nginx's rate-limit rejections (503s) in 600 s. ntfy also records the
// requester on every 4xx/5xx (100 strikes in 10 min by default), and charges
// `up*` topics to the subscriber: a burst of 60, then one request per 5 s.
// Whether ntfy.sh still runs the documented numbers is unknown, so these
// follow them. The two jails are guarded separately: the send rate and the
// in-flight cap with its 503 pause keep nginx quiet, and the rejection
// budget keeps every other rejection under the ban feed.

/// Send burst for ntfy.sh, shared by every user. Below nginx's 1000.
pub const NTFY_BURST: f64 = 300.0;

/// Send tokens per second for ntfy.sh: 80% of nginx's 0.75 per second, so
/// its rate limit should never reject us. That caps ntfy.sh at about 51,800
/// pushes a day for every user together.
pub const NTFY_REFILL_PER_SEC: f64 = 0.6;

/// Sends to ntfy.sh in flight at once. Should nginx answer 503 anyway, at
/// most this many strikes land before the pause, and each resume is at
/// least `NTFY_PAUSE_ON_503_SECS` apart: under 10 in any 600 s.
pub const NTFY_MAX_IN_FLIGHT: u32 = 4;

/// How long a 503 from ntfy.sh pauses every send to it, in seconds of
/// rejection-budget refill.
pub const NTFY_PAUSE_ON_503_SECS: f64 = 300.0;

/// Rejections of any kind ntfy.sh may give us before its sends pause. With
/// the refill this allows at most 60 in any 600 s, 60% of the ban feed's
/// 100, so a few stale subscriptions cannot pause ntfy.sh for everyone.
pub const NTFY_REJECT_BURST: f64 = 20.0;

/// One ntfy.sh rejection is earned back every 15 s.
pub const NTFY_REJECT_REFILL_PER_SEC: f64 = 1.0 / 15.0;

/// Burst per (user, ntfy.sh): half of what ntfy gives one subscriber.
pub const NTFY_USER_BURST: f64 = 30.0;

/// Tokens per second per (user, ntfy.sh): ntfy's per-subscriber one per 5 s,
/// so a busy user's phone does not answer 429.
pub const NTFY_USER_REFILL_PER_SEC: f64 = 0.2;

/// Send burst per generic destination key. Every user's sends to one
/// destination share it, so it is the backstop.
pub const IP_BURST: f64 = 300.0;

/// Send tokens refilled per second per generic destination key.
pub const IP_REFILL_PER_SEC: f64 = 30.0;

/// Sends to one generic destination in flight at once. The rejection
/// budget caps it at the same number anyway.
pub const IP_MAX_IN_FLIGHT: u32 = 20;

/// A 503 from a generic destination is an ordinary rejection.
pub const IP_PAUSE_ON_503_SECS: f64 = 0.0;

/// Rejections a generic destination may give us before its sends pause.
/// With the refill this allows at most 60 in any 600 s, 60% of ntfy's
/// default 100 for self-hosted servers.
pub const IP_REJECT_BURST: f64 = 20.0;

/// One generic rejection is earned back every 15 s.
pub const IP_REJECT_REFILL_PER_SEC: f64 = 1.0 / 15.0;

/// Burst per (user, generic destination key). It counts pushes, not
/// messages, so it leaves room for a user with several UnifiedPush devices
/// in a busy group.
pub const USER_BURST: f64 = 60.0;

/// Tokens refilled per second per (user, generic destination key).
pub const USER_REFILL_PER_SEC: f64 = 3.0;

/// How long a 429 from the push server holds back that user's sends to that
/// destination, in seconds of refill.
pub const USER_429_COOLDOWN_SECS: f64 = 30.0;

/// Most generic entries the destination map holds. The ntfy.sh entry is
/// never evicted and not counted, so the map can hold one more.
pub const MAX_DEST_KEYS: usize = 4096;

/// Most entries the (user, destination) map holds.
pub const MAX_USER_KEYS: usize = 16384;

/// Most entries the subscription map holds.
pub const MAX_SUB_KEYS: usize = 16384;

/// First cooldown after a subscription's push is rejected, in seconds. Each
/// later rejection doubles it.
pub const SUB_COOLDOWN_BASE_SECS: u64 = 300;

/// Longest subscription cooldown, in seconds, and the one a rejection that
/// removes the subscription gets at once. UnifiedPush has no retry, so a
/// phone back online after a day can miss up to this much push.
pub const SUB_COOLDOWN_MAX_SECS: u64 = 3600;

/// How often `first_refusal` says yes for one subscription.
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(3600);

/// How long a subscription entry is kept once it carries no live state.
const SUB_FORGET_AFTER: Duration = Duration::from_secs(3600);

/// Users counted per destination for the pause report and `top_senders`.
const MAX_OFFENDERS: usize = 16;

/// Users named in the pause report and by `top_senders`.
const TOP_OFFENDERS: usize = 3;

/// Which limits a send is counted against. The caller builds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DestKey {
    /// ntfy.sh and its subdomains, keyed by host so that more resolved
    /// addresses cannot multiply its budgets: a ban is per our IP.
    Ntfy,
    /// Any other destination, keyed by its normalized address.
    Ip(IpAddr),
}

/// The limits for one kind of destination key.
#[derive(Debug, Clone, PartialEq)]
pub struct DestLimits {
    pub send_burst: f64,
    pub send_refill_per_sec: f64,
    pub reject_burst: f64,
    pub reject_refill_per_sec: f64,
    pub user_burst: f64,
    pub user_refill_per_sec: f64,
    pub max_in_flight: u32,
    /// Seconds of rejection-budget refill a 503 pauses for; 0 treats a 503
    /// as an ordinary rejection.
    pub pause_on_503_secs: f64,
}

impl DestLimits {
    fn send(&self) -> Rate {
        Rate {
            burst: self.send_burst,
            refill_per_sec: self.send_refill_per_sec,
        }
    }

    fn reject(&self) -> Rate {
        Rate {
            burst: self.reject_burst,
            refill_per_sec: self.reject_refill_per_sec,
        }
    }

    fn user(&self) -> Rate {
        Rate {
            burst: self.user_burst,
            refill_per_sec: self.user_refill_per_sec,
        }
    }
}

/// Every tunable of an `UpLimiter`.
#[derive(Debug, Clone, PartialEq)]
pub struct UpLimits {
    pub ntfy: DestLimits,
    pub generic: DestLimits,
    pub user_429_cooldown_secs: f64,
    pub max_dest_keys: usize,
    pub max_user_keys: usize,
    pub max_sub_keys: usize,
    pub sub_cooldown_base_secs: u64,
    pub sub_cooldown_max_secs: u64,
}

impl UpLimits {
    fn dest(&self, key: DestKey) -> &DestLimits {
        match key {
            DestKey::Ntfy => &self.ntfy,
            DestKey::Ip(_) => &self.generic,
        }
    }
}

impl Default for UpLimits {
    fn default() -> Self {
        UpLimits {
            ntfy: DestLimits {
                send_burst: NTFY_BURST,
                send_refill_per_sec: NTFY_REFILL_PER_SEC,
                reject_burst: NTFY_REJECT_BURST,
                reject_refill_per_sec: NTFY_REJECT_REFILL_PER_SEC,
                user_burst: NTFY_USER_BURST,
                user_refill_per_sec: NTFY_USER_REFILL_PER_SEC,
                max_in_flight: NTFY_MAX_IN_FLIGHT,
                pause_on_503_secs: NTFY_PAUSE_ON_503_SECS,
            },
            generic: DestLimits {
                send_burst: IP_BURST,
                send_refill_per_sec: IP_REFILL_PER_SEC,
                reject_burst: IP_REJECT_BURST,
                reject_refill_per_sec: IP_REJECT_REFILL_PER_SEC,
                user_burst: USER_BURST,
                user_refill_per_sec: USER_REFILL_PER_SEC,
                max_in_flight: IP_MAX_IN_FLIGHT,
                pause_on_503_secs: IP_PAUSE_ON_503_SECS,
            },
            user_429_cooldown_secs: USER_429_COOLDOWN_SECS,
            max_dest_keys: MAX_DEST_KEYS,
            max_user_keys: MAX_USER_KEYS,
            max_sub_keys: MAX_SUB_KEYS,
            sub_cooldown_base_secs: SUB_COOLDOWN_BASE_SECS,
            sub_cooldown_max_secs: SUB_COOLDOWN_MAX_SECS,
        }
    }
}

/// The bucket that refused a send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    /// The destination's send bucket every user shares.
    Ip,
    /// The (user, destination) bucket.
    User,
    /// The destination's rejection budget is spent.
    Paused,
    /// The subscription is cooling down after a rejection.
    Subscription,
}

/// One user's rejections at one destination since the last pause report,
/// or, from `top_senders`, admitted sends since its last call. Once the
/// table is full a newcomer inherits the smallest count, so a count can
/// overstate but a heavy offender is never left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offender {
    pub user_id: String,
    pub rejections: u32,
}

/// What a rejection did to its destination's budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejected {
    Counted,
    /// This rejection spent the budget. `top` are the users with the most
    /// rejections since the last report, and `others` how many more users
    /// had some. The counts are cleared after each report.
    Paused {
        top: Vec<Offender>,
        others: u32,
    },
}

/// A push subscription: a hash of its session and endpoint, so a device
/// that registers a new endpoint starts clean. The endpoint is not kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubKey(pub u64);

impl SubKey {
    pub fn new(session_id: &str, endpoint: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        session_id.hash(&mut hasher);
        endpoint.hash(&mut hasher);
        SubKey(hasher.finish())
    }
}

/// Whether a send may go out.
#[derive(Debug)]
pub enum Admit<'a> {
    /// Send, then complete the ticket with the outcome.
    Allowed(Ticket<'a>),
    /// The rejection budget is fine, but sends in flight have reserved all
    /// of it. Wait for `UpLimiter::released` and ask again.
    Wait,
    /// `first` is true on the first denial since `bucket` last had room, so
    /// the caller can log once per episode.
    Denied { first: bool, bucket: Bucket },
}

/// An admitted send's reservation on its destination's rejection budget.
/// Complete it with `success` or `rejected`; dropping it otherwise (a
/// transport error, a failed build, cancellation) only gives the
/// reservation back. Never create or drop one while holding the limiter's
/// lock.
pub struct Ticket<'a> {
    limiter: &'a UpLimiter,
    user_id: String,
    sub: SubKey,
    key: DestKey,
    /// The destination entry this ticket reserved on. If that entry was
    /// evicted and created again, completing the ticket leaves it alone.
    generation: u64,
    /// Cleared once completed, so the reservation is released exactly once.
    armed: bool,
}

impl Ticket<'_> {
    /// The push server accepted the send: release the reservation at no
    /// cost and clear the subscription's cooldown.
    pub fn success(mut self) {
        self.armed = false;
        self.limiter
            .complete_success(self.key, self.generation, self.sub);
    }

    /// The push server answered with an HTTP rejection: release the
    /// reservation, spend a budget token, and cool the subscription down
    /// (for the longest cooldown if `prunes`). A 503 from ntfy.sh, its
    /// nginx rate limit, also pauses it for `pause_on_503_secs`.
    pub fn rejected(mut self, prunes: bool, status: Option<u16>, now: Instant) -> Rejected {
        self.armed = false;
        self.limiter.complete_rejected(
            &self.user_id,
            self.sub,
            self.key,
            self.generation,
            prunes,
            status,
            now,
        )
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.armed = false;
            self.limiter.release(self.key, self.generation);
        }
    }
}

impl fmt::Debug for Ticket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ticket")
            .field("user_id", &self.user_id)
            .field("sub", &self.sub)
            .field("key", &self.key)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct Rate {
    burst: f64,
    refill_per_sec: f64,
}

struct TokenBucket {
    tokens: f64,
    /// Latest time seen; refill counts from here.
    last: Instant,
    /// Whether this bucket has denied since it last held a whole token.
    denied: bool,
}

impl TokenBucket {
    fn full(rate: Rate, now: Instant) -> Self {
        TokenBucket {
            tokens: rate.burst,
            last: now,
            denied: false,
        }
    }

    /// Add what was earned since `last`, capped at the burst. Deliveries run
    /// as separate tasks, so `now` can be earlier than `last`: that adds
    /// nothing and keeps `last`, so no interval is counted twice.
    fn refill(&mut self, rate: Rate, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate.refill_per_sec).min(rate.burst);
        self.last = self.last.max(now);

        if self.tokens >= 1.0 {
            self.denied = false;
        }
    }

    fn is_full(&self, rate: Rate) -> bool {
        self.tokens >= rate.burst
    }

    /// Share of the burst left, for eviction.
    fn fullness(&self, rate: Rate) -> f64 {
        if rate.burst > 0.0 {
            self.tokens / rate.burst
        } else {
            1.0
        }
    }

    /// Record a denial. True if it is the first of this empty episode.
    fn deny(&mut self) -> bool {
        let first = !self.denied;
        self.denied = true;
        first
    }
}

struct Dest {
    send: TokenBucket,
    reject: TokenBucket,
    /// Admitted sends not yet completed, each holding a reject token.
    in_flight: u32,
    offenders: Vec<Offender>,
    /// Admitted sends per user since the last `top_senders`.
    senders: Vec<Offender>,
    /// The call counter when this entry was last used, for eviction ties.
    touched: u64,
    /// Unique per entry created, so a ticket from before an eviction cannot
    /// release or spend on the entry that replaced it.
    generation: u64,
}

impl Dest {
    fn new(limits: &DestLimits, now: Instant, generation: u64) -> Self {
        Dest {
            send: TokenBucket::full(limits.send(), now),
            reject: TokenBucket::full(limits.reject(), now),
            in_flight: 0,
            offenders: Vec::new(),
            senders: Vec::new(),
            touched: 0,
            generation,
        }
    }

    fn refill(&mut self, limits: &DestLimits, now: Instant) {
        self.send.refill(limits.send(), now);
        self.reject.refill(limits.reject(), now);
    }

    fn paused(&self) -> bool {
        self.reject.tokens < 1.0
    }

    /// Evicting it would hand back a spent budget or lose a reservation.
    fn protected(&self) -> bool {
        self.paused() || self.in_flight > 0
    }

    /// Would come back identical if evicted.
    fn idle_full(&self, limits: &DestLimits) -> bool {
        self.send.is_full(limits.send())
            && self.reject.is_full(limits.reject())
            && self.in_flight == 0
            && !self.paused()
    }

    fn fullness(&self, limits: &DestLimits) -> f64 {
        self.send
            .fullness(limits.send())
            .min(self.reject.fullness(limits.reject()))
    }

    fn release(&mut self) {
        self.in_flight = self.in_flight.saturating_sub(1);
    }

    /// Release a reservation as a rejection by `user_id`. An ordinary
    /// rejection spends one token but never takes the budget below 0, nor
    /// lifts a 503 pause; a `pause` sets the budget far enough below 0 that
    /// it takes `pause_on_503_secs` to refill. The pause is reported only by
    /// the rejection that starts it.
    fn reject_one(
        &mut self,
        limits: &DestLimits,
        user_id: &str,
        pause: bool,
        now: Instant,
    ) -> Rejected {
        self.release();
        self.reject.refill(limits.reject(), now);

        let before = self.reject.tokens;
        let spent = (before - 1.0).max(before.min(0.0));
        self.reject.tokens = if pause {
            spent.min(-(limits.pause_on_503_secs * limits.reject_refill_per_sec))
        } else {
            spent
        };

        record_offender(&mut self.offenders, user_id);

        if before >= 1.0 && self.reject.tokens < 1.0 {
            pause_report(&mut self.offenders)
        } else {
            Rejected::Counted
        }
    }
}

struct UserEntry {
    bucket: TokenBucket,
    /// The call counter when this entry was last used, for eviction ties.
    touched: u64,
}

#[derive(Default)]
struct SubEntry {
    /// End of the current cooldown; `None` once cleared by a success.
    until: Option<Instant>,
    /// Length of the latest cooldown in seconds, 0 when none.
    level_secs: u64,
    /// Whether `admit` has refused this subscription in this cooldown.
    denied: bool,
    /// When `first_refusal` last said yes.
    refused_at: Option<Instant>,
}

impl SubEntry {
    fn cooling(&self, now: Instant) -> bool {
        self.until.is_some_and(|until| now < until)
    }

    /// When this entry stops carrying live state.
    fn end(&self) -> Option<Instant> {
        let refusal = self.refused_at.map(|at| at + REFUSAL_LOG_INTERVAL);
        self.until.max(refusal)
    }

    fn deny(&mut self) -> bool {
        let first = !self.denied;
        self.denied = true;
        first
    }

    /// Start or extend the cooldown after a rejection. A rejection that
    /// lands during a cooldown came from a send already in flight, so it
    /// does not escalate; a pruning one goes straight to the cap.
    fn cool(&mut self, prunes: bool, now: Instant, limits: &UpLimits) {
        let active = self.cooling(now);

        if prunes {
            self.level_secs = limits.sub_cooldown_max_secs;
        } else if active {
            return;
        } else if self.level_secs == 0 {
            self.level_secs = limits.sub_cooldown_base_secs;
        } else {
            self.level_secs = self.level_secs.saturating_mul(2);
        }
        self.level_secs = self.level_secs.min(limits.sub_cooldown_max_secs);

        let until = now + Duration::from_secs(self.level_secs);
        self.until = Some(self.until.map_or(until, |current| current.max(until)));

        if !active {
            self.denied = false;
        }
    }

    /// Forget the cooldown. True if nothing is left worth keeping.
    fn clear_cooldown(&mut self) -> bool {
        self.until = None;
        self.level_secs = 0;
        self.denied = false;
        self.refused_at.is_none()
    }
}

#[derive(Default)]
struct State {
    dest: HashMap<DestKey, Dest>,
    user: HashMap<(String, DestKey), UserEntry>,
    subs: HashMap<SubKey, SubEntry>,
    /// Bumped on every call, stamped into each entry's `touched`.
    calls: u64,
    /// Bumped for every destination entry created, stamped into it.
    generations: u64,
}

/// Per-destination, per-(user, destination) and per-subscription limits for
/// UnifiedPush sends. One instance is shared by every delivery.
pub struct UpLimiter {
    limits: UpLimits,
    state: Mutex<State>,
    /// Woken on every ticket release, for sends told to `Wait`.
    released: Notify,
}

impl UpLimiter {
    pub fn new() -> Self {
        Self::with(UpLimits::default())
    }

    /// A limiter with explicit limits. Each map keeps at least one entry,
    /// so a maximum of 0 acts as 1.
    pub fn with(mut limits: UpLimits) -> Self {
        limits.max_dest_keys = limits.max_dest_keys.max(1);
        limits.max_user_keys = limits.max_user_keys.max(1);
        limits.max_sub_keys = limits.max_sub_keys.max(1);

        UpLimiter {
            limits,
            state: Mutex::new(State::default()),
            released: Notify::new(),
        }
    }

    /// Admit a send by `user_id` on subscription `sub` to `key`, taking a
    /// token from both buckets and reserving a reject token, or take
    /// nothing and say why. A cooling subscription is refused before any
    /// other entry is touched. The destination is checked before the user,
    /// so an exhausted destination is never blamed on whichever user
    /// happened to hit it.
    pub fn admit(&self, user_id: &str, sub: SubKey, key: DestKey, now: Instant) -> Admit<'_> {
        let generation = {
            let mut state = self.lock();
            let State {
                dest: dests,
                user: users,
                subs,
                calls,
                generations,
            } = &mut *state;
            *calls = calls.wrapping_add(1);

            if let Some(entry) = subs.get_mut(&sub) {
                if entry.cooling(now) {
                    return Admit::Denied {
                        first: entry.deny(),
                        bucket: Bucket::Subscription,
                    };
                }
            }

            let dest = dest_for(dests, key, &self.limits, now, *calls, generations);

            if dest.paused() {
                return Admit::Denied {
                    first: dest.reject.deny(),
                    bucket: Bucket::Paused,
                };
            }

            let dest_limits = self.limits.dest(key);
            if dest.in_flight >= dest_limits.max_in_flight
                || dest.reject.tokens - f64::from(dest.in_flight) < 1.0
            {
                return Admit::Wait;
            }

            if dest.send.tokens < 1.0 {
                return Admit::Denied {
                    first: dest.send.deny(),
                    bucket: Bucket::Ip,
                };
            }

            let user = user_for(users, user_id, key, &self.limits, now, *calls);

            if user.tokens < 1.0 {
                return Admit::Denied {
                    first: user.deny(),
                    bucket: Bucket::User,
                };
            }

            dest.send.tokens -= 1.0;
            user.tokens -= 1.0;
            dest.in_flight = dest.in_flight.saturating_add(1);
            record_offender(&mut dest.senders, user_id);
            dest.generation
        };

        Admit::Allowed(Ticket {
            limiter: self,
            user_id: user_id.to_owned(),
            sub,
            key,
            generation,
            armed: true,
        })
    }

    /// Resolves after the next ticket release. After a `Wait`, create it
    /// BEFORE calling `admit` again: it is armed from creation, so a
    /// release in between is not missed.
    pub fn released(&self) -> Notified<'_> {
        self.released.notified()
    }

    /// Hold back `user_id`'s sends to `key` for about
    /// `user_429_cooldown_secs` after a 429. The tokens are set, not
    /// reduced, so repeated 429s cannot push the bucket further down. The
    /// destination bucket is left alone: ntfy answers 429 per subscriber on
    /// `up*` topics, and one user's 429 must not stall everyone else.
    pub fn drain_user(&self, user_id: &str, key: DestKey, now: Instant) {
        let rate = self.limits.dest(key).user();
        let mut state = self.lock();
        let State { user, calls, .. } = &mut *state;
        *calls = calls.wrapping_add(1);

        let bucket = user_for(user, user_id, key, &self.limits, now, *calls);
        bucket.tokens = -(self.limits.user_429_cooldown_secs * rate.refill_per_sec);
    }

    /// The users with the most admitted sends to `key` since the last call,
    /// most first, and how many more users sent, so the caller can blame a
    /// drained send bucket on who drained it. Clears that table. A key with
    /// no entry has none. In each `Offender`, `rejections` counts sends.
    pub fn top_senders(&self, key: DestKey) -> (Vec<Offender>, u32) {
        match self.lock().dest.get_mut(&key) {
            Some(dest) => take_top(&mut dest.senders),
            None => (Vec::new(), 0),
        }
    }

    /// True at most once an hour per subscription, so the caller can log a
    /// refused endpoint without flooding.
    pub fn first_refusal(&self, sub: SubKey, now: Instant) -> bool {
        let mut state = self.lock();
        let entry = sub_entry(&mut state.subs, sub, self.limits.max_sub_keys, now);

        let due = entry
            .refused_at
            .is_none_or(|at| now.saturating_duration_since(at) >= REFUSAL_LOG_INTERVAL);
        if due {
            entry.refused_at = Some(now);
        }
        due
    }

    fn release(&self, key: DestKey, generation: u64) {
        release_slot(&mut self.lock().dest, key, generation);
        self.released.notify_waiters();
    }

    fn complete_success(&self, key: DestKey, generation: u64, sub: SubKey) {
        {
            let mut state = self.lock();
            let State { dest, subs, .. } = &mut *state;
            release_slot(dest, key, generation);

            if subs.get_mut(&sub).is_some_and(SubEntry::clear_cooldown) {
                subs.remove(&sub);
            }
        }

        self.released.notify_waiters();
    }

    fn complete_rejected(
        &self,
        user_id: &str,
        sub: SubKey,
        key: DestKey,
        generation: u64,
        prunes: bool,
        status: Option<u16>,
        now: Instant,
    ) -> Rejected {
        let limits = self.limits.dest(key);
        let pause = status == Some(503) && limits.pause_on_503_secs > 0.0;

        let rejected = {
            let mut state = self.lock();
            let State {
                dest, subs, calls, ..
            } = &mut *state;
            *calls = calls.wrapping_add(1);

            // An evicted destination, or the entry that replaced it, has
            // nothing of this ticket's to release or count against.
            let rejected = match live_dest(dest, key, generation) {
                Some(dest) => {
                    dest.touched = *calls;
                    dest.reject_one(limits, user_id, pause, now)
                }
                None => Rejected::Counted,
            };

            sub_entry(subs, sub, self.limits.max_sub_keys, now).cool(prunes, now, &self.limits);
            rejected
        };

        self.released.notify_waiters();
        rejected
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

/// The entry for `key` if it is still the one a ticket of `generation`
/// reserved on.
fn live_dest(map: &mut HashMap<DestKey, Dest>, key: DestKey, generation: u64) -> Option<&mut Dest> {
    map.get_mut(&key)
        .filter(|dest| dest.generation == generation)
}

/// Give back one reservation. An evicted destination is left absent, and an
/// entry created since is left alone.
fn release_slot(map: &mut HashMap<DestKey, Dest>, key: DestKey, generation: u64) {
    if let Some(dest) = live_dest(map, key, generation) {
        dest.release();
    }
}

/// Count one rejection for `user_id`. Space-saving: when the table is full
/// the smallest entry is replaced and its count inherited, so a late heavy
/// offender still climbs into the top.
fn record_offender(offenders: &mut Vec<Offender>, user_id: &str) {
    if let Some(offender) = offenders.iter_mut().find(|o| o.user_id == user_id) {
        offender.rejections = offender.rejections.saturating_add(1);
        return;
    }

    if offenders.len() < MAX_OFFENDERS {
        offenders.push(Offender {
            user_id: user_id.to_owned(),
            rejections: 1,
        });
        return;
    }

    if let Some(smallest) = offenders.iter_mut().min_by_key(|o| o.rejections) {
        let rejections = smallest.rejections.saturating_add(1);
        *smallest = Offender {
            user_id: user_id.to_owned(),
            rejections,
        };
    }
}

/// The top of a space-saving table, highest count first, and how many more
/// users it held. Empties the table.
fn take_top(table: &mut Vec<Offender>) -> (Vec<Offender>, u32) {
    let mut all = std::mem::take(table);
    all.sort_by(|a, b| {
        b.rejections
            .cmp(&a.rejections)
            .then_with(|| a.user_id.cmp(&b.user_id))
    });

    let others = all.len().saturating_sub(TOP_OFFENDERS) as u32;
    all.truncate(TOP_OFFENDERS);
    (all, others)
}

/// The pause report, most rejections first. Empties the table.
fn pause_report(offenders: &mut Vec<Offender>) -> Rejected {
    let (top, others) = take_top(offenders);
    Rejected::Paused { top, others }
}

/// Eviction order: the fullest entry first, since it would come back nearly
/// the same, then the least recently touched.
fn evict_first(a: (f64, u64), b: (f64, u64)) -> Ordering {
    b.0.total_cmp(&a.0).then(a.1.cmp(&b.1))
}

/// The destination entry for `key`, refilled to `now` and stamped as
/// touched. A new key starts full and is never refused for lack of room.
fn dest_for<'m>(
    map: &'m mut HashMap<DestKey, Dest>,
    key: DestKey,
    limits: &UpLimits,
    now: Instant,
    calls: u64,
    generations: &mut u64,
) -> &'m mut Dest {
    if evictable(&key) && !map.contains_key(&key) {
        make_dest_room(map, limits, now);
    }

    let dest_limits = limits.dest(key);
    let dest = map.entry(key).or_insert_with(|| {
        *generations = generations.wrapping_add(1);
        Dest::new(dest_limits, now, *generations)
    });

    dest.refill(dest_limits, now);
    dest.touched = calls;
    dest
}

/// Whether a destination entry may be evicted. The ntfy.sh entry never is:
/// one key holds its whole budget, and a fresh entry would hand out a fresh
/// budget while the old sends are still in flight.
fn evictable(key: &DestKey) -> bool {
    *key != DestKey::Ntfy
}

/// Make room for one more generic destination. Idle-full entries go first,
/// then the fullest. A paused entry or one with sends in flight goes only if
/// every candidate is one.
fn make_dest_room(map: &mut HashMap<DestKey, Dest>, limits: &UpLimits, now: Instant) {
    let candidates = |map: &HashMap<DestKey, Dest>| map.keys().filter(|key| evictable(key)).count();

    if candidates(map) < limits.max_dest_keys {
        return;
    }

    map.retain(|key, dest| {
        let dest_limits = limits.dest(*key);
        dest.refill(dest_limits, now);
        !evictable(key) || !dest.idle_full(dest_limits)
    });

    while candidates(map) >= limits.max_dest_keys {
        let all_protected = map
            .iter()
            .filter(|(key, _)| evictable(key))
            .all(|(_, dest)| dest.protected());
        let score = |key: DestKey, dest: &Dest| (dest.fullness(limits.dest(key)), dest.touched);

        let Some(victim) = map
            .iter()
            .filter(|(key, dest)| evictable(key) && (all_protected || !dest.protected()))
            .min_by(|(ka, a), (kb, b)| evict_first(score(**ka, *a), score(**kb, *b)))
            .map(|(key, _)| *key)
        else {
            break;
        };

        map.remove(&victim);
    }
}

/// The (user, destination) bucket, refilled to `now` and stamped as
/// touched. A new pair starts full and is never refused for lack of room.
fn user_for<'m>(
    map: &'m mut HashMap<(String, DestKey), UserEntry>,
    user_id: &str,
    key: DestKey,
    limits: &UpLimits,
    now: Instant,
    calls: u64,
) -> &'m mut TokenBucket {
    let pair = (user_id.to_owned(), key);
    if !map.contains_key(&pair) {
        make_user_room(map, limits, now);
    }

    let rate = limits.dest(key).user();
    let entry = map.entry(pair).or_insert_with(|| UserEntry {
        bucket: TokenBucket::full(rate, now),
        touched: 0,
    });

    entry.bucket.refill(rate, now);
    entry.touched = calls;
    &mut entry.bucket
}

/// Make room for one more (user, destination) pair. Full buckets go first,
/// then the fullest, so a drained pair outlives a flood of new ones.
fn make_user_room(
    map: &mut HashMap<(String, DestKey), UserEntry>,
    limits: &UpLimits,
    now: Instant,
) {
    if map.len() < limits.max_user_keys {
        return;
    }

    map.retain(|(_, key), entry| {
        let rate = limits.dest(*key).user();
        entry.bucket.refill(rate, now);
        !entry.bucket.is_full(rate)
    });

    while map.len() >= limits.max_user_keys {
        let score = |key: DestKey, entry: &UserEntry| {
            (
                entry.bucket.fullness(limits.dest(key).user()),
                entry.touched,
            )
        };

        let Some(victim) = map
            .iter()
            .min_by(|(pa, a), (pb, b)| evict_first(score(pa.1, *a), score(pb.1, *b)))
            .map(|(pair, _)| pair.clone())
        else {
            break;
        };

        map.remove(&victim);
    }
}

/// The subscription entry for `sub`, created empty if absent.
fn sub_entry(
    map: &mut HashMap<SubKey, SubEntry>,
    sub: SubKey,
    max_keys: usize,
    now: Instant,
) -> &mut SubEntry {
    if !map.contains_key(&sub) {
        make_sub_room(map, max_keys, now);
    }

    map.entry(sub).or_default()
}

/// Make room for one more subscription. Entries that ended more than
/// `SUB_FORGET_AFTER` ago go first, then the one that ended longest ago or
/// ends soonest.
fn make_sub_room(map: &mut HashMap<SubKey, SubEntry>, max_keys: usize, now: Instant) {
    if map.len() < max_keys {
        return;
    }

    map.retain(|_, entry| {
        entry
            .end()
            .is_some_and(|end| now.saturating_duration_since(end) < SUB_FORGET_AFTER)
    });

    while map.len() >= max_keys {
        let Some(victim) = map
            .iter()
            .min_by_key(|(_, entry)| entry.end())
            .map(|(sub, _)| *sub)
        else {
            break;
        };

        map.remove(&victim);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv4Addr;

    const SUB: SubKey = SubKey(0);

    /// A generic destination key in TEST-NET-3.
    fn key(n: u8) -> DestKey {
        DestKey::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, n)))
    }

    fn after(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    fn secs(base: Instant, secs: f64) -> Instant {
        base + Duration::from_secs_f64(secs)
    }

    /// Volume limits for both key kinds, with a rejection budget too large
    /// to matter.
    fn volume(
        send_burst: f64,
        send_refill_per_sec: f64,
        user_burst: f64,
        user_refill_per_sec: f64,
        max_keys: usize,
    ) -> UpLimits {
        let generic = DestLimits {
            send_burst,
            send_refill_per_sec,
            reject_burst: 1e9,
            reject_refill_per_sec: 0.0,
            user_burst,
            user_refill_per_sec,
            max_in_flight: u32::MAX,
            pause_on_503_secs: 0.0,
        };

        UpLimits {
            ntfy: generic.clone(),
            generic,
            max_dest_keys: max_keys,
            max_user_keys: max_keys,
            max_sub_keys: max_keys,
            ..UpLimits::default()
        }
    }

    /// The defaults with another generic rejection budget.
    fn generic_budget(reject_burst: f64, reject_refill_per_sec: f64) -> UpLimits {
        let defaults = UpLimits::default();
        UpLimits {
            generic: DestLimits {
                reject_burst,
                reject_refill_per_sec,
                ..defaults.generic.clone()
            },
            ..defaults
        }
    }

    #[track_caller]
    fn allowed(admit: Admit<'_>) -> Ticket<'_> {
        match admit {
            Admit::Allowed(ticket) => ticket,
            other => panic!("expected Allowed, got {other:?}"),
        }
    }

    #[track_caller]
    fn assert_wait(admit: Admit<'_>) {
        assert!(matches!(admit, Admit::Wait), "expected Wait, got {admit:?}");
    }

    #[track_caller]
    fn assert_denied(admit: Admit<'_>, first: bool, bucket: Bucket) {
        match admit {
            Admit::Denied {
                first: got_first,
                bucket: got_bucket,
            } => assert_eq!((got_first, got_bucket), (first, bucket)),
            other => panic!("expected Denied {{ {first}, {bucket:?} }}, got {other:?}"),
        }
    }

    #[track_caller]
    fn denied_bucket(admit: Admit<'_>) -> Bucket {
        match admit {
            Admit::Denied { bucket, .. } => bucket,
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    fn offender(user_id: &str, rejections: u32) -> Offender {
        Offender {
            user_id: user_id.to_string(),
            rejections,
        }
    }

    /// Admit and reject at once, on a subscription of its own.
    fn strike(limiter: &UpLimiter, user: &str, sub: u64, key: DestKey, now: Instant) -> Rejected {
        allowed(limiter.admit(user, SubKey(sub), key, now)).rejected(false, Some(507), now)
    }

    fn send_tokens(limiter: &UpLimiter, key: DestKey) -> Option<f64> {
        limiter.lock().dest.get(&key).map(|dest| dest.send.tokens)
    }

    fn reject_tokens(limiter: &UpLimiter, key: DestKey) -> Option<f64> {
        limiter.lock().dest.get(&key).map(|dest| dest.reject.tokens)
    }

    fn in_flight(limiter: &UpLimiter, key: DestKey) -> Option<u32> {
        limiter.lock().dest.get(&key).map(|dest| dest.in_flight)
    }

    fn user_tokens(limiter: &UpLimiter, user: &str, key: DestKey) -> Option<f64> {
        let state = limiter.lock();
        state
            .user
            .get(&(user.to_string(), key))
            .map(|entry| entry.bucket.tokens)
    }

    fn map_sizes(limiter: &UpLimiter) -> (usize, usize, usize) {
        let state = limiter.lock();
        (state.dest.len(), state.user.len(), state.subs.len())
    }

    fn dest_keys(limiter: &UpLimiter) -> Vec<DestKey> {
        let mut keys: Vec<_> = limiter.lock().dest.keys().copied().collect();
        keys.sort();
        keys
    }

    fn user_keys(limiter: &UpLimiter) -> Vec<(String, DestKey)> {
        let mut keys: Vec<_> = limiter.lock().user.keys().cloned().collect();
        keys.sort();
        keys
    }

    fn user_key(user: &str, n: u8) -> (String, DestKey) {
        (user.to_string(), key(n))
    }

    #[test]
    fn burst_admits_then_denies() {
        let limiter = UpLimiter::with(volume(100.0, 0.0, 3.0, 0.0, 16));
        let t0 = Instant::now();

        for _ in 0..3 {
            allowed(limiter.admit("a", SUB, key(1), t0));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);
    }

    #[test]
    fn partial_refill_after_elapsed() {
        let limiter = UpLimiter::with(volume(100.0, 0.0, 10.0, 2.0, 16));
        let t0 = Instant::now();

        for _ in 0..10 {
            allowed(limiter.admit("a", SUB, key(1), t0));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);

        // 1.5 s at 2 per second earns 3 tokens.
        let t1 = after(t0, 1500);
        for _ in 0..3 {
            allowed(limiter.admit("a", SUB, key(1), t1));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t1), true, Bucket::User);
    }

    #[test]
    fn tokens_cap_at_burst() {
        let limiter = UpLimiter::with(volume(100.0, 0.0, 3.0, 1.0, 16));
        let t0 = Instant::now();

        for _ in 0..3 {
            allowed(limiter.admit("a", SUB, key(1), t0));
        }

        // 100 s of refill still leaves only the burst.
        let t1 = after(t0, 100_000);
        for _ in 0..3 {
            allowed(limiter.admit("a", SUB, key(1), t1));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t1), true, Bucket::User);
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));
    }

    #[test]
    fn destination_keys_are_independent() {
        let limiter = UpLimiter::with(volume(2.0, 0.0, 100.0, 0.0, 16));
        let t0 = Instant::now();

        for n in [1, 2] {
            for _ in 0..2 {
                allowed(limiter.admit("a", SUB, key(n), t0));
            }
            assert_denied(limiter.admit("a", SUB, key(n), t0), true, Bucket::Ip);
        }
    }

    #[test]
    fn user_bucket_caps_one_user_only() {
        let limiter = UpLimiter::with(volume(100.0, 0.0, 3.0, 0.0, 16));
        let t0 = Instant::now();

        for _ in 0..3 {
            allowed(limiter.admit("a", SUB, key(1), t0));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);

        // Another user sending to the same destination is unaffected.
        for _ in 0..3 {
            allowed(limiter.admit("b", SUB, key(1), t0));
        }
    }

    #[test]
    fn destination_bucket_caps_across_users() {
        let limiter = UpLimiter::with(volume(5.0, 0.0, 2.0, 0.0, 64));
        let t0 = Instant::now();

        for n in 0..5 {
            allowed(limiter.admit(&format!("u{n}"), SUB, key(1), t0));
        }

        // Every later user still has tokens, so the destination is blamed.
        for n in 5..10 {
            assert_denied(
                limiter.admit(&format!("u{n}"), SUB, key(1), t0),
                n == 5,
                Bucket::Ip,
            );
        }
    }

    #[test]
    fn denial_takes_no_token() {
        let t0 = Instant::now();

        // Refused by the user bucket: the destination keeps its tokens.
        let limiter = UpLimiter::with(volume(5.0, 0.0, 1.0, 0.0, 16));
        allowed(limiter.admit("a", SUB, key(1), t0));
        assert_eq!(send_tokens(&limiter, key(1)), Some(4.0));
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);
        assert_eq!(send_tokens(&limiter, key(1)), Some(4.0));
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));
        assert_eq!(in_flight(&limiter, key(1)), Some(0));

        // Refused by the destination bucket: no user bucket loses a token.
        let limiter = UpLimiter::with(volume(1.0, 0.0, 5.0, 0.0, 16));
        allowed(limiter.admit("a", SUB, key(1), t0));
        assert_denied(limiter.admit("b", SUB, key(1), t0), true, Bucket::Ip);
        assert_eq!(user_tokens(&limiter, "b", key(1)), None);
        assert_denied(limiter.admit("a", SUB, key(1), t0), false, Bucket::Ip);
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(4.0));
        assert_eq!(send_tokens(&limiter, key(1)), Some(0.0));
    }

    #[test]
    fn drain_user_cools_down_only_that_pair() {
        let limiter = UpLimiter::with(volume(1000.0, 0.0, 6.0, USER_REFILL_PER_SEC, 16));
        let t0 = Instant::now();

        allowed(limiter.admit("a", SUB, key(1), t0));
        allowed(limiter.admit("b", SUB, key(1), t0));
        allowed(limiter.admit("a", SUB, key(2), t0));
        let destination = send_tokens(&limiter, key(1));

        limiter.drain_user("a", key(1), t0);

        assert_eq!(
            user_tokens(&limiter, "a", key(1)),
            Some(-(USER_429_COOLDOWN_SECS * USER_REFILL_PER_SEC))
        );
        assert_eq!(send_tokens(&limiter, key(1)), destination);
        assert_eq!(user_tokens(&limiter, "b", key(1)), Some(5.0));
        assert_eq!(user_tokens(&limiter, "a", key(2)), Some(5.0));

        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);
        allowed(limiter.admit("b", SUB, key(1), t0));
        allowed(limiter.admit("a", SUB, key(2), t0));

        // Still held back just before the cooldown ends...
        let cooldown = Duration::from_secs_f64(USER_429_COOLDOWN_SECS);
        let almost = t0 + cooldown - Duration::from_millis(1);
        assert_denied(limiter.admit("a", SUB, key(1), almost), false, Bucket::User);

        // ...and admitted once it has passed and a token has been earned.
        let later = t0 + cooldown + Duration::from_secs(1);
        allowed(limiter.admit("a", SUB, key(1), later));
    }

    #[test]
    fn drain_user_with_no_refill_still_denies() {
        let limiter = UpLimiter::with(volume(5.0, 0.0, 5.0, 0.0, 16));
        let t0 = Instant::now();

        allowed(limiter.admit("a", SUB, key(1), t0));
        limiter.drain_user("a", key(1), t0);

        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));
        assert_denied(
            limiter.admit("a", SUB, key(1), after(t0, 3_600_000)),
            true,
            Bucket::User,
        );
        allowed(limiter.admit("b", SUB, key(1), t0));
    }

    #[test]
    fn drain_user_sets_rather_than_subtracts() {
        let limiter = UpLimiter::with(volume(5.0, 0.0, 5.0, 1.0, 16));
        let t0 = Instant::now();
        let drained = Some(-USER_429_COOLDOWN_SECS);

        // An unknown pair gets an entry; the destination map is not touched.
        limiter.drain_user("a", key(1), t0);
        assert_eq!(user_tokens(&limiter, "a", key(1)), drained);
        assert_eq!(send_tokens(&limiter, key(1)), None);

        limiter.drain_user("a", key(1), t0);
        assert_eq!(user_tokens(&limiter, "a", key(1)), drained);
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);
    }

    #[test]
    fn drain_user_uses_the_key_kinds_refill() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        limiter.drain_user("a", DestKey::Ntfy, t0);
        limiter.drain_user("a", key(1), t0);

        assert_eq!(
            user_tokens(&limiter, "a", DestKey::Ntfy),
            Some(-(USER_429_COOLDOWN_SECS * NTFY_USER_REFILL_PER_SEC))
        );
        assert_eq!(
            user_tokens(&limiter, "a", key(1)),
            Some(-(USER_429_COOLDOWN_SECS * USER_REFILL_PER_SEC))
        );
    }

    #[test]
    fn first_is_tracked_per_bucket() {
        let t0 = Instant::now();
        let t1 = after(t0, 1000);

        // True once per empty episode, and again after a refill.
        let limiter = UpLimiter::with(volume(100.0, 0.0, 1.0, 1.0, 16));
        allowed(limiter.admit("a", SUB, key(1), t0));
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);
        assert_denied(limiter.admit("a", SUB, key(1), t0), false, Bucket::User);
        allowed(limiter.admit("a", SUB, key(1), t1));
        assert_denied(limiter.admit("a", SUB, key(1), t1), true, Bucket::User);

        // The destination bucket keeps its own flag.
        let limiter = UpLimiter::with(volume(2.0, 1.0, 1.0, 1.0, 16));
        allowed(limiter.admit("a", SUB, key(1), t0));
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);
        allowed(limiter.admit("b", SUB, key(1), t0));
        assert_denied(limiter.admit("c", SUB, key(1), t0), true, Bucket::Ip);
        assert_denied(limiter.admit("d", SUB, key(1), t0), false, Bucket::Ip);
        // Both empty: the destination is reported.
        assert_denied(limiter.admit("a", SUB, key(1), t0), false, Bucket::Ip);
        allowed(limiter.admit("c", SUB, key(1), t1));
        assert_denied(limiter.admit("d", SUB, key(1), t1), true, Bucket::Ip);

        // A denial reported as the destination's leaves the user's flag armed.
        let limiter = UpLimiter::with(volume(1.0, 1.0, 1.0, 0.0, 16));
        allowed(limiter.admit("a", SUB, key(1), t0));
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::Ip);
        assert_denied(limiter.admit("a", SUB, key(1), t1), true, Bucket::User);
    }

    #[test]
    fn out_of_order_now_neither_panics_nor_double_refills() {
        let limiter = UpLimiter::with(volume(100.0, 0.0, 2.0, 1.0, 16));
        let t0 = Instant::now();
        let t10 = after(t0, 10_000);

        for _ in 0..2 {
            allowed(limiter.admit("a", SUB, key(1), t10));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t10), true, Bucket::User);

        // A delivery stamped before the bucket's last update earns nothing.
        assert_denied(limiter.admit("a", SUB, key(1), t0), false, Bucket::User);
        limiter.drain_user("b", key(1), t10);
        limiter.drain_user("b", key(1), t0);
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.0));

        // Back in order, only time after t10 counts, and only once.
        let t10_5 = after(t0, 10_500);
        assert_denied(limiter.admit("a", SUB, key(1), t10_5), false, Bucket::User);
        assert_eq!(user_tokens(&limiter, "a", key(1)), Some(0.5));
        allowed(limiter.admit("a", SUB, key(1), after(t0, 11_000)));
        assert_denied(
            limiter.admit("a", SUB, key(1), after(t0, 11_000)),
            true,
            Bucket::User,
        );

        // The drained pair's cooldown runs from t10, not from t0.
        assert_denied(
            limiter.admit("b", SUB, key(1), after(t0, 39_000)),
            true,
            Bucket::User,
        );
    }

    #[test]
    fn key_flood_stays_bounded() {
        let max_keys = 8;
        let t0 = Instant::now();

        // Many destinations, each from its own user and subscription.
        let limiter = UpLimiter::with(volume(2.0, 0.0, 2.0, 0.0, max_keys));
        for n in 0..1000u32 {
            let ip = DestKey::Ip(IpAddr::V4(Ipv4Addr::from(n)));
            // A new key is never refused for lack of room.
            let sub = SubKey(u64::from(n) + 1);
            let ticket = allowed(limiter.admit(&format!("u{n}"), sub, ip, t0));
            ticket.rejected(n % 2 == 0, Some(507), t0);
            assert!(limiter.first_refusal(SubKey(u64::from(n) + 5000), t0));

            let (dests, users, subs) = map_sizes(&limiter);
            assert!(
                dests <= max_keys && users <= max_keys && subs <= max_keys,
                "{dests}/{users}/{subs} at {ip:?}"
            );
        }

        // The buckets still count after the churn.
        for _ in 0..2 {
            allowed(limiter.admit("z", SUB, key(1), t0));
        }
        assert_denied(limiter.admit("z", SUB, key(1), t0), true, Bucket::Ip);

        // Many users, one destination.
        let limiter = UpLimiter::with(volume(1_000_000.0, 0.0, 2.0, 0.0, max_keys));
        for n in 0..1000 {
            allowed(limiter.admit(&format!("u{n}"), SUB, key(1), t0));
            assert!(map_sizes(&limiter).1 <= max_keys, "user u{n}");
        }
        assert_eq!(map_sizes(&limiter).0, 1);
    }

    #[test]
    fn idle_full_buckets_are_pruned_first() {
        let limiter = UpLimiter::with(volume(2.0, 1.0, 2.0, 1.0, 3));
        let t0 = Instant::now();

        // Keys 2 and 3 are emptied; key 1 keeps one token.
        for n in [2, 3] {
            for _ in 0..2 {
                allowed(limiter.admit("u", SUB, key(n), t0));
            }
        }
        allowed(limiter.admit("u", SUB, key(1), t0));

        // A second later key 1 is full again; keys 2 and 3 are not.
        allowed(limiter.admit("u", SUB, key(4), after(t0, 1000)));

        assert_eq!(dest_keys(&limiter), vec![key(2), key(3), key(4)]);
        assert_eq!(
            user_keys(&limiter),
            vec![user_key("u", 2), user_key("u", 3), user_key("u", 4)]
        );
    }

    #[test]
    fn ties_are_evicted_least_recently_touched_first() {
        let limiter = UpLimiter::with(volume(2.0, 0.0, 2.0, 0.0, 3));
        let t0 = Instant::now();

        for n in [1, 2, 3] {
            allowed(limiter.admit("u", SUB, key(n), t0));
        }
        // Key 1 is emptied; keys 2 and 3 tie, and key 2 is older.
        allowed(limiter.admit("u", SUB, key(1), t0));

        allowed(limiter.admit("u", SUB, key(4), t0));
        assert_eq!(dest_keys(&limiter), vec![key(1), key(3), key(4)]);
        assert_eq!(
            user_keys(&limiter),
            vec![user_key("u", 1), user_key("u", 3), user_key("u", 4)]
        );

        // An evicted key comes back with a full allowance.
        for _ in 0..2 {
            allowed(limiter.admit("u", SUB, key(2), t0));
        }
        assert_eq!(map_sizes(&limiter), (3, 3, 0));
    }

    #[test]
    fn fullest_is_evicted_before_older_drained() {
        let t0 = Instant::now();

        // Users: "old" is half drained and touched first, "new" barely used.
        let limits = UpLimits {
            max_user_keys: 2,
            ..volume(1000.0, 0.0, 10.0, 0.0, 16)
        };
        let limiter = UpLimiter::with(limits);
        for _ in 0..5 {
            allowed(limiter.admit("old", SUB, key(1), t0));
        }
        allowed(limiter.admit("new", SUB, key(1), t0));
        allowed(limiter.admit("third", SUB, key(1), t0));
        assert_eq!(
            user_keys(&limiter),
            vec![user_key("old", 1), user_key("third", 1)]
        );

        // Destinations, the same way.
        let limits = UpLimits {
            max_dest_keys: 2,
            ..volume(10.0, 0.0, 1000.0, 0.0, 16)
        };
        let limiter = UpLimiter::with(limits);
        for _ in 0..5 {
            allowed(limiter.admit("u", SUB, key(1), t0));
        }
        allowed(limiter.admit("u", SUB, key(2), t0));
        allowed(limiter.admit("u", SUB, key(3), t0));
        assert_eq!(dest_keys(&limiter), vec![key(1), key(3)]);
    }

    #[test]
    fn drained_user_survives_key_flood() {
        let limiter = UpLimiter::with(UpLimits {
            max_user_keys: 4,
            ..UpLimits::default()
        });
        let t0 = Instant::now();

        limiter.drain_user("victim", key(1), t0);
        for n in 0..100 {
            allowed(limiter.admit(&format!("u{n}"), SubKey(n), key(1), t0));
        }

        assert!(map_sizes(&limiter).1 <= 4);
        assert_denied(limiter.admit("victim", SUB, key(1), t0), true, Bucket::User);
    }

    #[test]
    fn full_maps_of_cooldowns_still_admit() {
        let t0 = Instant::now();

        // Every user drained.
        let limiter = UpLimiter::with(UpLimits {
            max_user_keys: 3,
            ..UpLimits::default()
        });
        for n in 0..3 {
            limiter.drain_user(&format!("d{n}"), key(1), t0);
        }
        allowed(limiter.admit("fresh", SUB, key(1), t0));
        assert_eq!(map_sizes(&limiter).1, 3);

        // Every destination paused.
        let limiter = UpLimiter::with(UpLimits {
            max_dest_keys: 2,
            ..generic_budget(1.0, 0.0)
        });
        for n in [1, 2] {
            strike(&limiter, "u", n.into(), key(n), t0);
            assert_denied(limiter.admit("u", SUB, key(n), t0), true, Bucket::Paused);
        }
        allowed(limiter.admit("u", SUB, key(3), t0));
        assert_eq!(map_sizes(&limiter).0, 2);

        // Every subscription cooling down.
        let limiter = UpLimiter::with(UpLimits {
            max_sub_keys: 2,
            ..UpLimits::default()
        });
        for n in 1..=3 {
            strike(&limiter, "u", n, key(1), t0);
            assert_eq!(
                denied_bucket(limiter.admit("u", SubKey(n), key(1), t0)),
                Bucket::Subscription
            );
        }
        assert_eq!(map_sizes(&limiter).2, 2);
    }

    #[test]
    fn paused_destination_is_not_evicted() {
        let t0 = Instant::now();
        let limits = UpLimits {
            generic: DestLimits {
                send_burst: 10.0,
                send_refill_per_sec: 1.0,
                reject_burst: 1.0,
                reject_refill_per_sec: 0.0,
                ..UpLimits::default().generic
            },
            max_dest_keys: 2,
            ..UpLimits::default()
        };
        let limiter = UpLimiter::with(limits);

        // Key 1 is paused and touched first; key 2 is drained by five.
        strike(&limiter, "u", 1, key(1), t0);
        for _ in 0..5 {
            allowed(limiter.admit("u", SUB, key(2), t0));
        }

        // Two seconds on, key 1's send bucket is full again; key 2's is not.
        let t2 = secs(t0, 2.0);
        allowed(limiter.admit("u", SUB, key(3), t2));
        assert_eq!(send_tokens(&limiter, key(1)), Some(10.0));
        assert_eq!(dest_keys(&limiter), vec![key(1), key(3)]);
        assert_denied(limiter.admit("u", SUB, key(1), t2), true, Bucket::Paused);

        // A destination with a send in flight is kept the same way.
        let limiter = UpLimiter::with(UpLimits {
            max_dest_keys: 2,
            ..volume(10.0, 0.0, 1000.0, 0.0, 16)
        });
        let held = allowed(limiter.admit("u", SUB, key(1), t0));
        for _ in 0..5 {
            allowed(limiter.admit("u", SUB, key(2), t0));
        }
        allowed(limiter.admit("u", SUB, key(3), t0));
        assert_eq!(dest_keys(&limiter), vec![key(1), key(3)]);
        held.success();
        assert_eq!(in_flight(&limiter, key(1)), Some(0));
    }

    #[test]
    fn paused_ntfy_survives_ip_key_flood() {
        let limiter = UpLimiter::with(UpLimits {
            max_dest_keys: 4,
            ..UpLimits::default()
        });
        let t0 = Instant::now();

        let ticket = allowed(limiter.admit("u", SubKey(1), DestKey::Ntfy, t0));
        assert!(matches!(
            ticket.rejected(false, Some(503), t0),
            Rejected::Paused { .. }
        ));

        // A minute on the paused entry's send bucket is full.
        let t60 = secs(t0, 60.0);
        for n in 0..100u32 {
            let ip = DestKey::Ip(IpAddr::V4(Ipv4Addr::from(n)));
            allowed(limiter.admit("f", SUB, ip, t60));
        }

        assert_eq!(send_tokens(&limiter, DestKey::Ntfy), Some(NTFY_BURST));
        assert_eq!(
            denied_bucket(limiter.admit("u", SUB, DestKey::Ntfy, t60)),
            Bucket::Paused
        );
    }

    #[test]
    fn release_of_evicted_destination_creates_no_entry() {
        let t0 = Instant::now();
        let limits = UpLimits {
            max_dest_keys: 1,
            ..volume(10.0, 0.0, 10.0, 0.0, 16)
        };

        // Every candidate is protected, so the one in flight goes.
        let limiter = UpLimiter::with(limits.clone());
        let held = allowed(limiter.admit("u", SubKey(1), key(1), t0));
        allowed(limiter.admit("u", SUB, key(2), t0));
        assert_eq!(dest_keys(&limiter), vec![key(2)]);

        assert_eq!(held.rejected(false, Some(507), t0), Rejected::Counted);
        assert_eq!(dest_keys(&limiter), vec![key(2)]);
        // The subscription is cooled all the same.
        assert_eq!(
            denied_bucket(limiter.admit("u", SubKey(1), key(2), t0)),
            Bucket::Subscription
        );

        for succeed in [true, false] {
            let limiter = UpLimiter::with(limits.clone());
            let held = allowed(limiter.admit("u", SUB, key(1), t0));
            allowed(limiter.admit("u", SUB, key(2), t0));
            if succeed {
                held.success();
            } else {
                drop(held);
            }
            assert_eq!(dest_keys(&limiter), vec![key(2)]);
        }
    }

    #[test]
    fn ntfy_entry_is_never_evicted() {
        let limiter = UpLimiter::with(UpLimits {
            max_dest_keys: 2,
            ..UpLimits::default()
        });
        let t0 = Instant::now();

        // ntfy.sh's budget is fully reserved, with no rejections yet.
        let _ntfy: Vec<_> = (0..4)
            .map(|n| allowed(limiter.admit(&format!("n{n}"), SubKey(n + 1), DestKey::Ntfy, t0)))
            .collect();
        strike(&limiter, "s", 10, key(1), t0);
        let _held = allowed(limiter.admit("h", SubKey(11), key(1), t0));

        allowed(limiter.admit("k", SubKey(12), key(2), t0));
        assert_wait(limiter.admit("w", SubKey(13), DestKey::Ntfy, t0));

        // A third generic key evicts a generic one; ntfy.sh is not counted.
        allowed(limiter.admit("k", SubKey(14), key(3), t0));
        assert_wait(limiter.admit("w", SubKey(13), DestKey::Ntfy, t0));
        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(4));
        assert_eq!(map_sizes(&limiter).0, 3);
        assert!(dest_keys(&limiter).contains(&DestKey::Ntfy));
    }

    #[test]
    fn old_tickets_leave_a_recreated_entry_alone() {
        let limiter = UpLimiter::with(UpLimits {
            max_dest_keys: 1,
            ..UpLimits::default()
        });
        let t0 = Instant::now();

        let old: Vec<_> = (1..=3)
            .map(|n| allowed(limiter.admit("a", SubKey(n), key(1), t0)))
            .collect();

        // Key 1 is evicted for key 2, then created again for a new send.
        allowed(limiter.admit("x", SUB, key(2), t0));
        let new = allowed(limiter.admit("n", SubKey(4), key(1), t0));
        assert_eq!(dest_keys(&limiter), vec![key(1)]);
        assert_eq!(in_flight(&limiter, key(1)), Some(1));
        assert_eq!(reject_tokens(&limiter, key(1)), Some(IP_REJECT_BURST));

        let mut old = old.into_iter();
        old.next().expect("first old ticket").success();
        let rejected = old
            .next()
            .expect("second old ticket")
            .rejected(false, Some(507), t0);
        assert_eq!(rejected, Rejected::Counted);
        drop(old);

        assert_eq!(in_flight(&limiter, key(1)), Some(1));
        assert_eq!(reject_tokens(&limiter, key(1)), Some(IP_REJECT_BURST));
        // The rejected ticket's subscription is cooled all the same.
        assert_eq!(
            denied_bucket(limiter.admit("a", SubKey(2), key(1), t0)),
            Bucket::Subscription
        );

        // The new ticket still counts.
        new.rejected(false, Some(507), t0);
        assert_eq!(in_flight(&limiter, key(1)), Some(0));
        assert_eq!(reject_tokens(&limiter, key(1)), Some(IP_REJECT_BURST - 1.0));
    }

    #[test]
    fn defaults_match_the_constants() {
        let limits = UpLimits::default();
        assert_eq!(limits.ntfy.send_burst, NTFY_BURST);
        assert_eq!(limits.ntfy.send_refill_per_sec, 0.6);
        assert_eq!(limits.ntfy.reject_burst, 20.0);
        assert_eq!(limits.ntfy.reject_refill_per_sec, 1.0 / 15.0);
        assert_eq!(limits.ntfy.user_burst, 30.0);
        assert_eq!(limits.ntfy.user_refill_per_sec, 0.2);
        assert_eq!(limits.ntfy.max_in_flight, 4);
        assert_eq!(limits.ntfy.pause_on_503_secs, 300.0);
        assert_eq!(limits.generic.send_burst, 300.0);
        assert_eq!(limits.generic.send_refill_per_sec, 30.0);
        assert_eq!(limits.generic.reject_burst, 20.0);
        assert_eq!(limits.generic.reject_refill_per_sec, 1.0 / 15.0);
        assert_eq!(limits.generic.user_burst, 60.0);
        assert_eq!(limits.generic.user_refill_per_sec, 3.0);
        assert_eq!(limits.generic.max_in_flight, 20);
        assert_eq!(limits.generic.pause_on_503_secs, 0.0);
        assert_eq!(limits.user_429_cooldown_secs, 30.0);
        assert_eq!(
            (
                limits.max_dest_keys,
                limits.max_user_keys,
                limits.max_sub_keys
            ),
            (4096, 16384, 16384)
        );
        assert_eq!(
            (limits.sub_cooldown_base_secs, limits.sub_cooldown_max_secs),
            (300, 3600)
        );

        // Rejections allowed in 600 s, burst plus refill, stay at 60% of the
        // ban feed's 100. Strikes for ntfy.sh's jail, at most a full set of
        // sends in flight per 503 pause, stay under its 10.
        let window = |l: &DestLimits| l.reject_burst + l.reject_refill_per_sec * 600.0;
        assert!(window(&limits.ntfy) <= 60.0 + 1e-9);
        assert!(window(&limits.generic) <= 60.0 + 1e-9);
        let jail = f64::from(limits.ntfy.max_in_flight) * (600.0 / limits.ntfy.pause_on_503_secs);
        assert!(jail < 10.0);

        assert_eq!(UpLimiter::new().limits, limits);
        assert_eq!(UpLimiter::default().limits, limits);

        let t0 = Instant::now();
        let limiter = UpLimiter::new();
        for _ in 0..USER_BURST as usize {
            allowed(limiter.admit("a", SUB, key(1), t0));
        }
        assert_denied(limiter.admit("a", SUB, key(1), t0), true, Bucket::User);

        let limiter = UpLimiter::default();
        for n in 0..IP_BURST as usize {
            allowed(limiter.admit(&format!("u{n}"), SUB, key(1), t0));
        }
        assert_denied(limiter.admit("late", SUB, key(1), t0), true, Bucket::Ip);
    }

    #[test]
    fn ntfy_key_uses_ntfy_limits() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        // Per user: 30, not the generic 60.
        for _ in 0..30 {
            allowed(limiter.admit("u0", SUB, DestKey::Ntfy, t0));
        }
        assert_denied(
            limiter.admit("u0", SUB, DestKey::Ntfy, t0),
            true,
            Bucket::User,
        );

        // Per destination: 300, then 0.6 a second.
        for n in 1..10 {
            for _ in 0..30 {
                allowed(limiter.admit(&format!("u{n}"), SUB, DestKey::Ntfy, t0));
            }
        }
        assert_denied(
            limiter.admit("late", SUB, DestKey::Ntfy, t0),
            true,
            Bucket::Ip,
        );

        let t10 = secs(t0, 10.0);
        for n in 0..6 {
            allowed(limiter.admit(&format!("v{n}"), SUB, DestKey::Ntfy, t10));
        }
        assert_denied(
            limiter.admit("late", SUB, DestKey::Ntfy, t10),
            true,
            Bucket::Ip,
        );

        // Generic keys are not affected.
        allowed(limiter.admit("u0", SUB, key(1), t0));
    }

    #[test]
    fn ntfy_budget_pauses_after_20_rejections() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        for n in 0..19 {
            assert_eq!(
                strike(&limiter, "a", n, DestKey::Ntfy, t0),
                Rejected::Counted
            );
        }
        assert_eq!(
            strike(&limiter, "b", 19, DestKey::Ntfy, t0),
            Rejected::Paused {
                top: vec![offender("a", 19), offender("b", 1)],
                others: 0
            }
        );

        assert_denied(
            limiter.admit("c", SubKey(40), DestKey::Ntfy, t0),
            true,
            Bucket::Paused,
        );
        assert_denied(
            limiter.admit("c", SubKey(40), DestKey::Ntfy, t0),
            false,
            Bucket::Paused,
        );
    }

    #[test]
    fn ntfy_budget_resumes_after_refill() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        for n in 1..=20 {
            strike(&limiter, "a", n, DestKey::Ntfy, t0);
        }
        assert_eq!(reject_tokens(&limiter, DestKey::Ntfy), Some(0.0));

        assert_eq!(
            denied_bucket(limiter.admit("b", SUB, DestKey::Ntfy, secs(t0, 14.9))),
            Bucket::Paused
        );

        // One token back after 15 s: one send at a time.
        let t15 = secs(t0, 15.001);
        let ticket = allowed(limiter.admit("b", SUB, DestKey::Ntfy, t15));
        assert_wait(limiter.admit("c", SUB, DestKey::Ntfy, t15));
        ticket.success();
        allowed(limiter.admit("c", SUB, DestKey::Ntfy, t15));
    }

    #[test]
    fn stale_ntfy_subscriptions_do_not_pause_it() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        // Two dozen dead devices, one rejection every 150 s for an hour.
        for n in 0..24 {
            let now = secs(t0, n as f64 * 150.0);
            assert_eq!(
                strike(&limiter, &format!("s{n}"), n + 1, DestKey::Ntfy, now),
                Rejected::Counted
            );
            allowed(limiter.admit("live", SUB, DestKey::Ntfy, now));
        }
    }

    /// An adversary for an hour: every second it sends to ntfy.sh as much as
    /// it is let, each send answered with `status` three seconds later. The
    /// second of each rejection.
    fn adversarial_hour(status: u16) -> Vec<u64> {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();
        let mut held: Vec<(Instant, Ticket<'_>)> = Vec::new();
        let mut strikes = Vec::new();
        let mut n = 0u64;

        for second in 0..=3600u64 {
            let now = secs(t0, second as f64);

            let (due, waiting): (Vec<_>, Vec<_>) = held
                .into_iter()
                .partition(|(at, _)| now.saturating_duration_since(*at) >= Duration::from_secs(3));
            held = waiting;
            for (_, ticket) in due {
                ticket.rejected(false, Some(status), now);
                strikes.push(second);
            }

            loop {
                n += 1;
                match limiter.admit(&format!("u{n}"), SubKey(n), DestKey::Ntfy, now) {
                    Admit::Allowed(ticket) => held.push((now, ticket)),
                    _ => break,
                }
            }
        }

        strikes
    }

    /// The most strikes in any closed 600 s window.
    fn worst_window(strikes: &[u64]) -> usize {
        (0..strikes.len())
            .map(|i| {
                strikes[i..]
                    .iter()
                    .take_while(|at| **at <= strikes[i] + 600)
                    .count()
            })
            .max()
            .unwrap_or(0)
    }

    #[test]
    fn ntfy_adversarial_hour_stays_under_both_jails() {
        // Every rejection feeds the ban feed (100 in 600 s).
        let rejections = adversarial_hour(507);
        let worst = worst_window(&rejections);
        assert!(worst <= 60, "{worst} rejections in 600 s");
        assert!(rejections.len() >= 200, "only {}", rejections.len());

        // Only 503s feed the jail (10 in 600 s).
        let rate_limited = adversarial_hour(503);
        let worst = worst_window(&rate_limited);
        assert!(worst <= 8, "{worst} rate-limit strikes in 600 s");
        assert!(rate_limited.len() >= 10, "only {}", rate_limited.len());
    }

    #[test]
    fn in_flight_tickets_are_capped_by_the_budget() {
        let t0 = Instant::now();
        let cases = [
            (UpLimits::default(), DestKey::Ntfy, 4),
            (UpLimits::default(), key(1), 20),
            // A budget below the in-flight cap is the binding limit.
            (generic_budget(3.0, 0.0), key(1), 3),
        ];

        for (limits, dest, expected) in cases {
            let limiter = UpLimiter::with(limits);
            let mut tickets = Vec::new();

            for n in 0..30 {
                match limiter.admit(&format!("u{n}"), SubKey(n), dest, t0) {
                    Admit::Allowed(ticket) => tickets.push(ticket),
                    Admit::Wait => {}
                    other => panic!("{other:?}"),
                }
            }

            assert_eq!(tickets.len(), expected, "{dest:?}");
            assert_eq!(in_flight(&limiter, dest), Some(expected as u32));
        }
    }

    #[test]
    fn ntfy_in_flight_is_capped_at_four_with_a_full_budget() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        let _tickets: Vec<_> = (0..4)
            .map(|n| allowed(limiter.admit(&format!("u{n}"), SubKey(n), DestKey::Ntfy, t0)))
            .collect();

        assert_wait(limiter.admit("w", SubKey(10), DestKey::Ntfy, t0));
        assert_eq!(
            reject_tokens(&limiter, DestKey::Ntfy),
            Some(NTFY_REJECT_BURST)
        );
        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(NTFY_MAX_IN_FLIGHT));
    }

    #[test]
    fn completing_one_ticket_admits_exactly_one_more() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        let mut tickets: Vec<_> = (0..4)
            .map(|n| allowed(limiter.admit(&format!("u{n}"), SubKey(n), DestKey::Ntfy, t0)))
            .collect();
        assert_wait(limiter.admit("w", SubKey(10), DestKey::Ntfy, t0));

        tickets.pop().expect("four tickets").success();
        tickets.push(allowed(limiter.admit("w", SubKey(10), DestKey::Ntfy, t0)));
        assert_wait(limiter.admit("x", SubKey(11), DestKey::Ntfy, t0));

        drop(tickets.pop());
        tickets.push(allowed(limiter.admit("x", SubKey(11), DestKey::Ntfy, t0)));
        assert_wait(limiter.admit("y", SubKey(12), DestKey::Ntfy, t0));

        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(4));
        drop(tickets);
        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(0));
        assert_eq!(
            reject_tokens(&limiter, DestKey::Ntfy),
            Some(NTFY_REJECT_BURST)
        );
    }

    #[test]
    fn drop_releases_success_is_free_rejected_costs() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();
        let admit = |n: u64| allowed(limiter.admit("u", SubKey(n), DestKey::Ntfy, t0));

        drop(admit(1));
        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(0));
        assert_eq!(
            reject_tokens(&limiter, DestKey::Ntfy),
            Some(NTFY_REJECT_BURST)
        );

        admit(2).success();
        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(0));
        assert_eq!(
            reject_tokens(&limiter, DestKey::Ntfy),
            Some(NTFY_REJECT_BURST)
        );

        assert_eq!(admit(3).rejected(false, Some(507), t0), Rejected::Counted);
        assert_eq!(in_flight(&limiter, DestKey::Ntfy), Some(0));
        assert_eq!(
            reject_tokens(&limiter, DestKey::Ntfy),
            Some(NTFY_REJECT_BURST - 1.0)
        );
    }

    #[test]
    fn wait_when_budget_is_reserved_not_spent() {
        let limiter = UpLimiter::with(generic_budget(3.0, 0.0));
        let t0 = Instant::now();

        let _tickets: Vec<_> = (0..3)
            .map(|n| allowed(limiter.admit(&format!("u{n}"), SubKey(n), key(1), t0)))
            .collect();

        assert_wait(limiter.admit("w", SubKey(10), key(1), t0));
        assert_wait(limiter.admit("w", SubKey(10), key(1), t0));

        // Waiting spends nothing and touches no user entry.
        assert_eq!(reject_tokens(&limiter, key(1)), Some(3.0));
        assert_eq!(send_tokens(&limiter, key(1)), Some(IP_BURST - 3.0));
        assert_eq!(user_tokens(&limiter, "w", key(1)), None);
    }

    #[test]
    fn ntfy_503_pauses_at_once() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();
        let paused = Some(-(NTFY_PAUSE_ON_503_SECS * NTFY_REJECT_REFILL_PER_SEC));

        let a = allowed(limiter.admit("a", SubKey(1), DestKey::Ntfy, t0));
        let b = allowed(limiter.admit("b", SubKey(2), DestKey::Ntfy, t0));

        assert_eq!(
            a.rejected(false, Some(503), t0),
            Rejected::Paused {
                top: vec![offender("a", 1)],
                others: 0
            }
        );
        assert_eq!(reject_tokens(&limiter, DestKey::Ntfy), paused);

        // The other send in flight is only counted, and neither lifts nor
        // deepens the pause: one report per pause.
        assert_eq!(b.rejected(false, Some(507), t0), Rejected::Counted);
        assert_eq!(reject_tokens(&limiter, DestKey::Ntfy), paused);
        assert_denied(
            limiter.admit("c", SubKey(3), DestKey::Ntfy, t0),
            true,
            Bucket::Paused,
        );
    }

    #[test]
    fn ntfy_503_pause_lasts_until_the_budget_refills() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        let ticket = allowed(limiter.admit("a", SubKey(1), DestKey::Ntfy, t0));
        ticket.rejected(false, Some(503), t0);

        // 20 tokens below 0 at one per 15 s: back to 1 after 315 s.
        assert_eq!(
            denied_bucket(limiter.admit("b", SUB, DestKey::Ntfy, secs(t0, 314.9))),
            Bucket::Paused
        );
        allowed(limiter.admit("b", SUB, DestKey::Ntfy, secs(t0, 315.001)));
    }

    #[test]
    fn generic_503_does_not_pause() {
        let t0 = Instant::now();
        let limiter = UpLimiter::new();
        let ticket = allowed(limiter.admit("a", SubKey(1), key(1), t0));
        assert_eq!(ticket.rejected(false, Some(503), t0), Rejected::Counted);
        assert_eq!(reject_tokens(&limiter, key(1)), Some(IP_REJECT_BURST - 1.0));
        allowed(limiter.admit("c", SubKey(3), key(1), t0));
    }

    #[test]
    fn top_senders_names_the_heaviest_and_clears() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        for (user, sends) in [("a", 5), ("b", 3), ("c", 1), ("d", 2)] {
            for _ in 0..sends {
                allowed(limiter.admit(user, SUB, DestKey::Ntfy, t0));
            }
        }
        allowed(limiter.admit("g", SUB, key(1), t0));

        assert_eq!(
            limiter.top_senders(DestKey::Ntfy),
            (
                vec![offender("a", 5), offender("b", 3), offender("d", 2)],
                1
            )
        );
        // Cleared by the call, and kept per destination.
        assert_eq!(limiter.top_senders(DestKey::Ntfy), (vec![], 0));
        assert_eq!(limiter.top_senders(key(1)), (vec![offender("g", 1)], 0));
        assert_eq!(limiter.top_senders(key(9)), (vec![], 0));
    }

    #[test]
    fn send_table_is_bounded() {
        let limiter = UpLimiter::with(volume(1000.0, 0.0, 100.0, 0.0, 16));
        let t0 = Instant::now();
        let senders = |limiter: &UpLimiter| limiter.lock().dest[&key(1)].senders.len();

        for n in 0..40 {
            allowed(limiter.admit(&format!("u{n}"), SUB, key(1), t0));
            assert!(senders(&limiter) <= 16);
        }
        // A late heavy sender still climbs to the top.
        for _ in 0..10 {
            allowed(limiter.admit("heavy", SUB, key(1), t0));
        }
        assert_eq!(senders(&limiter), 16);

        let (top, others) = limiter.top_senders(key(1));
        assert_eq!(top.len(), 3);
        assert_eq!(top[0], offender("heavy", 12));
        assert_eq!(others, 13);
    }

    #[test]
    fn ntfy_429_does_not_pause_other_users() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        let ticket = allowed(limiter.admit("a", SubKey(1), DestKey::Ntfy, t0));
        assert_eq!(ticket.rejected(false, Some(429), t0), Rejected::Counted);
        assert_eq!(
            reject_tokens(&limiter, DestKey::Ntfy),
            Some(NTFY_REJECT_BURST - 1.0)
        );

        allowed(limiter.admit("b", SubKey(2), DestKey::Ntfy, t0));
        // Its subscription cools down like any other rejection.
        assert_denied(
            limiter.admit("a", SubKey(1), DestKey::Ntfy, t0),
            true,
            Bucket::Subscription,
        );
    }

    #[test]
    fn generic_budget_is_20_plus_one_per_15_s() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        for n in 1..20 {
            assert_eq!(strike(&limiter, "a", n, key(1), t0), Rejected::Counted);
        }
        assert_eq!(
            strike(&limiter, "a", 20, key(1), t0),
            Rejected::Paused {
                top: vec![offender("a", 20)],
                others: 0
            }
        );

        assert_denied(limiter.admit("b", SUB, key(1), t0), true, Bucket::Paused);
        assert_denied(
            limiter.admit("b", SUB, key(1), secs(t0, 14.9)),
            false,
            Bucket::Paused,
        );
        allowed(limiter.admit("b", SUB, key(1), secs(t0, 15.001)));
    }

    #[test]
    fn late_heavy_offender_is_named() {
        let limiter = UpLimiter::with(generic_budget(40.0, 0.0));
        let t0 = Instant::now();
        let mut sub = 0;
        let mut strike_as = |user: &str| {
            sub += 1;
            strike(&limiter, user, sub, key(1), t0)
        };

        // Sixteen early users fill the table.
        for n in 0..16 {
            assert_eq!(strike_as(&format!("u{n}")), Rejected::Counted);
        }

        // A late heavy offender takes the smallest slot and climbs.
        for _ in 0..5 {
            assert_eq!(strike_as("late"), Rejected::Counted);
        }

        // Nineteen more one-off users spend the budget.
        for n in 0..18 {
            assert_eq!(strike_as(&format!("v{n:02}")), Rejected::Counted);
        }
        assert_eq!(
            strike_as("v18"),
            Rejected::Paused {
                top: vec![offender("late", 6), offender("v15", 3), offender("v16", 3)],
                others: 13
            }
        );
    }

    #[test]
    fn offenders_are_cleared_after_each_pause() {
        let limiter = UpLimiter::with(generic_budget(2.0, 0.0));
        let t0 = Instant::now();

        assert_eq!(strike(&limiter, "a", 1, key(1), t0), Rejected::Counted);
        assert_eq!(
            strike(&limiter, "b", 2, key(1), t0),
            Rejected::Paused {
                top: vec![offender("a", 1), offender("b", 1)],
                others: 0
            }
        );

        // The next pause names only who caused it.
        limiter
            .lock()
            .dest
            .get_mut(&key(1))
            .expect("destination entry")
            .reject
            .tokens = 2.0;
        assert_eq!(strike(&limiter, "c", 3, key(1), t0), Rejected::Counted);
        assert_eq!(
            strike(&limiter, "c", 4, key(1), t0),
            Rejected::Paused {
                top: vec![offender("c", 2)],
                others: 0
            }
        );
    }

    #[test]
    fn subscription_cooldown_doubles_to_the_cap() {
        let limiter = UpLimiter::new();
        let sub = SubKey(7);
        let mut now = Instant::now();

        for cooldown in [300.0, 600.0, 1200.0, 2400.0, 3600.0, 3600.0] {
            let ticket = allowed(limiter.admit("a", sub, key(1), now));
            assert_eq!(ticket.rejected(false, Some(507), now), Rejected::Counted);

            assert_denied(
                limiter.admit("a", sub, key(1), secs(now, cooldown - 0.001)),
                true,
                Bucket::Subscription,
            );
            assert_denied(
                limiter.admit("b", sub, key(2), secs(now, cooldown - 0.001)),
                false,
                Bucket::Subscription,
            );
            now = secs(now, cooldown);
        }

        allowed(limiter.admit("a", sub, key(1), now));
    }

    #[test]
    fn in_flight_rejections_do_not_escalate_twice() {
        let limiter = UpLimiter::new();
        let sub = SubKey(7);
        let t0 = Instant::now();

        let tickets: Vec<_> = (0..3)
            .map(|_| allowed(limiter.admit("a", sub, key(1), t0)))
            .collect();
        for (n, ticket) in tickets.into_iter().enumerate() {
            ticket.rejected(false, Some(507), secs(t0, n as f64));
        }

        // Still the first period.
        assert_eq!(
            denied_bucket(limiter.admit("a", sub, key(1), secs(t0, 299.9))),
            Bucket::Subscription
        );
        let ticket = allowed(limiter.admit("a", sub, key(1), secs(t0, 300.0)));

        // The next rejection escalates once.
        ticket.rejected(false, Some(507), secs(t0, 300.0));
        assert_eq!(
            denied_bucket(limiter.admit("a", sub, key(1), secs(t0, 899.9))),
            Bucket::Subscription
        );
        allowed(limiter.admit("a", sub, key(1), secs(t0, 900.0)));
    }

    #[test]
    fn pruning_rejection_cools_for_the_max() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();

        let ticket = allowed(limiter.admit("a", SubKey(1), key(1), t0));
        ticket.rejected(true, Some(410), t0);
        assert_eq!(
            denied_bucket(limiter.admit("a", SubKey(1), key(1), secs(t0, 3599.9))),
            Bucket::Subscription
        );
        allowed(limiter.admit("a", SubKey(1), key(1), secs(t0, 3600.0)));

        // A prune landing during a short cooldown extends it to the max.
        let a = allowed(limiter.admit("a", SubKey(2), key(1), t0));
        let b = allowed(limiter.admit("a", SubKey(2), key(1), t0));
        a.rejected(false, Some(507), t0);
        b.rejected(true, Some(404), secs(t0, 10.0));
        assert_eq!(
            denied_bucket(limiter.admit("a", SubKey(2), key(1), secs(t0, 3609.9))),
            Bucket::Subscription
        );
        allowed(limiter.admit("a", SubKey(2), key(1), secs(t0, 3610.0)));
    }

    #[test]
    fn success_clears_the_cooldown() {
        let limiter = UpLimiter::new();
        let sub = SubKey(7);
        let t0 = Instant::now();

        // Two rejections first, so the level is 600 s.
        for start in [0.0, 300.0] {
            let now = secs(t0, start);
            allowed(limiter.admit("a", sub, key(1), now)).rejected(false, Some(507), now);
        }

        let t900 = secs(t0, 900.0);
        let a = allowed(limiter.admit("a", sub, key(1), t900));
        let b = allowed(limiter.admit("a", sub, key(1), t900));
        a.rejected(false, Some(507), t900);
        b.success();

        // Cleared at once, and the level starts over at 300 s.
        let ticket = allowed(limiter.admit("a", sub, key(1), t900));
        ticket.rejected(false, Some(507), t900);
        assert_eq!(
            denied_bucket(limiter.admit("a", sub, key(1), secs(t0, 1199.9))),
            Bucket::Subscription
        );
        allowed(limiter.admit("a", sub, key(1), secs(t0, 1200.0)));
    }

    #[test]
    fn cooldown_is_keyed_by_endpoint() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();
        let old = SubKey::new("session", "https://ntfy.sh/upAAAAAAAAAAAA");
        let new = SubKey::new("session", "https://ntfy.sh/upBBBBBBBBBBBB");
        let other = SubKey::new("other", "https://ntfy.sh/upAAAAAAAAAAAA");

        let ticket = allowed(limiter.admit("a", old, DestKey::Ntfy, t0));
        ticket.rejected(false, Some(507), t0);

        assert_eq!(
            denied_bucket(limiter.admit("a", old, DestKey::Ntfy, t0)),
            Bucket::Subscription
        );
        // A new endpoint for the same session, or another session, sends.
        allowed(limiter.admit("a", new, DestKey::Ntfy, t0));
        allowed(limiter.admit("b", other, DestKey::Ntfy, t0));
    }

    #[test]
    fn sub_key_hashes_session_and_endpoint() {
        let a = SubKey::new("session", "https://push.example.org/a");
        assert_eq!(a, SubKey::new("session", "https://push.example.org/a"));
        assert_ne!(a, SubKey::new("session", "https://push.example.org/b"));
        assert_ne!(a, SubKey::new("session2", "https://push.example.org/a"));
        // The two fields cannot run into each other.
        assert_ne!(SubKey::new("ab", "c"), SubKey::new("a", "bc"));
    }

    #[test]
    fn subscription_denial_creates_no_entries() {
        let limiter = UpLimiter::new();
        let sub = SubKey(7);
        let t0 = Instant::now();

        strike(&limiter, "a", 7, key(1), t0);
        let before = map_sizes(&limiter);

        assert_denied(
            limiter.admit("b", sub, key(2), t0),
            true,
            Bucket::Subscription,
        );
        assert_eq!(map_sizes(&limiter), before);
        assert_eq!(dest_keys(&limiter), vec![key(1)]);
        assert_eq!(user_tokens(&limiter, "b", key(2)), None);
    }

    #[test]
    fn first_refusal_once_per_hour() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();
        let (a, b) = (SubKey(1), SubKey(2));

        assert!(limiter.first_refusal(a, t0));
        assert!(!limiter.first_refusal(a, t0));
        assert!(!limiter.first_refusal(a, secs(t0, 3599.0)));
        assert!(limiter.first_refusal(b, t0));
        assert!(limiter.first_refusal(a, secs(t0, 3600.0)));
        assert!(!limiter.first_refusal(a, secs(t0, 3601.0)));

        // It is not a cooldown: the subscription still sends.
        allowed(limiter.admit("u", a, key(1), t0));
        assert_eq!(map_sizes(&limiter).2, 2);
    }

    #[tokio::test]
    async fn released_wakes_a_waiter() {
        let limiter = UpLimiter::new();
        let t0 = Instant::now();
        let patience = Duration::from_secs(5);

        // Nothing released: nothing wakes.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), limiter.released())
                .await
                .is_err()
        );

        for (round, how) in ["success", "drop", "rejected"].into_iter().enumerate() {
            let base = round as u64 * 10;
            let mut tickets: Vec<_> = (0..4)
                .map(|n| {
                    let user = format!("{how}{n}");
                    allowed(limiter.admit(&user, SubKey(base + n), DestKey::Ntfy, t0))
                })
                .collect();
            assert_wait(limiter.admit("w", SubKey(100), DestKey::Ntfy, t0));

            // Armed before the release, as the waiter must.
            let released = limiter.released();
            let ticket = tickets.pop().expect("four tickets");
            match how {
                "success" => ticket.success(),
                "drop" => drop(ticket),
                _ => {
                    ticket.rejected(false, Some(507), t0);
                }
            }

            tokio::time::timeout(patience, released)
                .await
                .unwrap_or_else(|_| panic!("{how} did not wake the waiter"));
        }
    }
}
