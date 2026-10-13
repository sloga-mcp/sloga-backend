use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant},
};

use lru::LruCache;
use revolt_database::{events::client::session_topic, Channel, Member, Server, User};
use tokio::sync::{Mutex, RwLock};

/// How many servers a connection may follow member events for at once
const ACTIVE_SERVERS_CAPACITY: usize = 5;

/// How long a `Subscribe` keeps a server's member events flowing
const ACTIVE_SERVERS_TTL: Duration = Duration::from_secs(900);

/// Servers the client asked to follow member events for, most recent last.
///
/// Bounded: touching a new key past capacity evicts the least recently
/// touched one and hands it back. Reads never refresh an entry, so an
/// entry expires `ttl` after its last `touch` no matter how often the set
/// is inspected. Holds no authority: the listener only subscribes the ids
/// that are also in its server cache.
#[derive(Debug)]
pub struct ActiveServers {
    capacity: usize,
    ttl: Duration,
    entries: Vec<(String, Instant)>,
}

impl ActiveServers {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        ActiveServers {
            capacity,
            ttl,
            entries: Vec::with_capacity(capacity),
        }
    }

    /// Insert or refresh `id`; returns the key evicted to make room, if any
    pub fn touch(&mut self, id: String, now: Instant) -> Option<String> {
        if let Some(index) = self.entries.iter().position(|(key, _)| key == &id) {
            self.entries.remove(index);
            self.entries.push((id, now));
            return None;
        }

        self.entries.push((id, now));
        if self.entries.len() > self.capacity {
            Some(self.entries.remove(0).0)
        } else {
            None
        }
    }

    /// Whether `id` is currently held, expired or not
    pub fn contains(&self, id: &str) -> bool {
        self.entries.iter().any(|(key, _)| key == id)
    }

    /// Drop `id`; returns whether it was held
    pub fn remove(&mut self, id: &str) -> bool {
        if let Some(index) = self.entries.iter().position(|(key, _)| key == id) {
            self.entries.remove(index);
            true
        } else {
            false
        }
    }

    /// Drop expired entries and return the rest, without refreshing them
    pub fn live_keys(&mut self, now: Instant) -> Vec<String> {
        let ttl = self.ttl;
        self.entries
            .retain(|(_, touched)| now.saturating_duration_since(*touched) < ttl);
        self.entries.iter().map(|(key, _)| key.clone()).collect()
    }
}

pub type SharedActiveServers = Arc<Mutex<ActiveServers>>;

/// Whether `id` looks like a ULID: 26 uppercase Crockford base32 characters
pub fn is_ulid_shaped(id: &str) -> bool {
    id.len() == 26
        && id.bytes().all(|b| {
            matches!(
                b,
                b'0'..=b'9' | b'A'..=b'H' | b'J' | b'K' | b'M' | b'N' | b'P'..=b'T' | b'V'..=b'Z'
            )
        })
}

/// Topic carrying a server's member events (`UserUpdate` and friends)
fn member_topic(server_id: &str) -> String {
    format!("{server_id}u")
}

/// Enumeration representing some change in subscriptions
pub enum SubscriptionStateChange {
    /// No change
    None,
    /// Clear all subscriptions
    Reset,
    /// Append or remove subscriptions
    Change {
        add: Vec<String>,
        remove: Vec<String>,
    },
}

/// Dumb per-state cache implementation
///
/// Ideally this would use a global cache that
/// allows for mutations and could use Rc<> to
/// track usage. If Rc<> == 1, then it only
/// remains in global cache, hence should be
/// dropped.
///
/// ------------------------------------------------
/// We can strip these objects to core information!!
/// ------------------------------------------------
#[derive(Debug)]
pub struct Cache {
    pub user_id: String,
    pub is_bot: bool,

    pub users: HashMap<String, User>,
    pub channels: HashMap<String, Channel>,
    pub members: HashMap<String, Member>,
    pub servers: HashMap<String, Server>,

    pub seen_events: LruCache<String, ()>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            user_id: Default::default(),
            is_bot: false,

            users: Default::default(),
            channels: Default::default(),
            members: Default::default(),
            servers: Default::default(),

            seen_events: LruCache::new(NonZeroUsize::new(20).unwrap()),
        }
    }
}

/// Client state
pub struct State {
    pub cache: Cache,

    pub session_id: String,
    pub private_topic: String,
    pub state: SubscriptionStateChange,

    pub subscribed: Arc<RwLock<HashSet<String>>>,
    pub active_servers: SharedActiveServers,

    /// Member topics (`{server}u`) this state subscribed and owns
    pub member_topics: HashSet<String>,
    /// Member topics to drop on the next `apply_state`
    member_topic_removals: HashSet<String>,
}

impl State {
    /// Create state from User
    pub fn from(user: User, session_id: String) -> State {
        let mut subscribed = HashSet::new();
        let private_topic = format!("{}!", user.id);
        subscribed.insert(private_topic.clone());
        subscribed.insert(user.id.clone());

        // Per-session topic: events that must reach only this connection
        // (e.g. a voice move carrying a device-bound token). Kept across
        // resets, see `reset_state`. Bots have no session (empty id), so
        // they get no session topic; `private_session` refuses empty ids.
        if !session_id.is_empty() {
            subscribed.insert(session_topic(&session_id));
        }

        // Privileged (platform moderator) sessions also listen on the global
        // topic, where moderation events such as ReportCreate are broadcast.
        // This is what delivers new-report notifications to moderators' live
        // clients; non-privileged users never subscribe here.
        if user.privileged {
            subscribed.insert("global".to_string());
        }

        let mut cache: Cache = Cache {
            user_id: user.id.clone(),
            ..Default::default()
        };

        cache.users.insert(user.id.clone(), user);

        State {
            cache,
            subscribed: Arc::new(RwLock::new(subscribed)),
            active_servers: Arc::new(Mutex::new(ActiveServers::new(
                ACTIVE_SERVERS_CAPACITY,
                ACTIVE_SERVERS_TTL,
            ))),
            member_topics: HashSet::new(),
            member_topic_removals: HashSet::new(),
            session_id,
            private_topic,
            state: SubscriptionStateChange::Reset,
        }
    }

    /// Apply currently queued state
    pub async fn apply_state(&mut self) -> SubscriptionStateChange {
        self.reconcile_member_topics().await;

        // Flush changes to subscriptions
        let state = std::mem::replace(&mut self.state, SubscriptionStateChange::None);
        let mut subscribed = self.subscribed.write().await;
        if let SubscriptionStateChange::Change { add, remove } = &state {
            for id in add {
                subscribed.insert(id.clone());
            }

            for id in remove {
                subscribed.remove(id);
            }
        }

        state
    }

    /// Bring the subscribed member topics in line with what this
    /// connection may see: bots follow every server they are in, users
    /// follow the servers they recently asked for that are also in the
    /// server cache. The cache is only filled from the user's own
    /// memberships (Ready, `ServerCreate`) and emptied on leave / delete,
    /// in this same task, so a `Subscribe` for a server the user is not
    /// (or no longer) in never yields a topic.
    async fn reconcile_member_topics(&mut self) {
        for topic in std::mem::take(&mut self.member_topic_removals) {
            self.unsubscribe_topic(&topic).await;
        }

        // Users: the live requested ids that are member servers. Bots: no
        // filter, every member server. Collected before touching
        // `subscribed`, so only one lock is held at a time.
        let requested: Option<HashSet<String>> = if self.cache.is_bot {
            None
        } else {
            let live = self.active_servers.lock().await.live_keys(Instant::now());
            Some(
                live.into_iter()
                    .filter(|id| self.cache.servers.contains_key(id))
                    .collect(),
            )
        };

        let unwanted: Vec<String> = self
            .member_topics
            .iter()
            .filter(|topic| {
                let id = topic.strip_suffix('u').unwrap_or(topic.as_str());
                !self.cache.servers.contains_key(id)
                    || requested.as_ref().is_some_and(|ids| !ids.contains(id))
            })
            .cloned()
            .collect();
        for topic in unwanted {
            self.member_topics.remove(&topic);
            self.unsubscribe_topic(&topic).await;
        }

        // Every tracked topic is now wanted, so equal counts mean nothing
        // is missing; spares a bot in many servers a pass per event.
        let missing: Vec<String> = match &requested {
            Some(ids) => ids
                .iter()
                .map(|id| member_topic(id))
                .filter(|topic| !self.member_topics.contains(topic))
                .collect(),
            None if self.member_topics.len() == self.cache.servers.len() => vec![],
            None => self
                .cache
                .servers
                .keys()
                .map(|id| member_topic(id))
                .filter(|topic| !self.member_topics.contains(topic))
                .collect(),
        };
        for topic in missing {
            // A topic already in `subscribed` but not tracked here (the
            // bot inserts at Ready / `ServerCreate`) is adopted rather
            // than subscribed twice.
            self.member_topics.insert(topic.clone());
            self.subscribe_topic(topic).await;
        }
    }

    /// Subscribe a member topic, in any subscription state
    async fn subscribe_topic(&mut self, topic: String) {
        let mut subscribed = self.subscribed.write().await;
        match &mut self.state {
            // The listener re-subscribes everything in `subscribed`
            SubscriptionStateChange::Reset => {}
            SubscriptionStateChange::Change { add, remove } => {
                if let Some(index) = remove.iter().position(|id| id == &topic) {
                    // Not flushed yet, so it is still subscribed upstream
                    remove.remove(index);
                } else if !subscribed.contains(&topic) {
                    add.push(topic.clone());
                }
            }
            SubscriptionStateChange::None => {
                if !subscribed.contains(&topic) {
                    self.state = SubscriptionStateChange::Change {
                        add: vec![topic.clone()],
                        remove: vec![],
                    };
                }
            }
        }

        subscribed.insert(topic);
    }

    /// Unsubscribe a member topic, in any subscription state
    async fn unsubscribe_topic(&mut self, topic: &str) {
        let mut subscribed = self.subscribed.write().await;
        match &mut self.state {
            // The listener re-subscribes everything in `subscribed`
            SubscriptionStateChange::Reset => {}
            SubscriptionStateChange::Change { add, remove } => {
                if let Some(index) = add.iter().position(|id| id == topic) {
                    // Not flushed yet, so it never reached upstream
                    add.remove(index);
                } else if subscribed.contains(topic) {
                    remove.push(topic.to_string());
                }
            }
            SubscriptionStateChange::None => {
                if subscribed.contains(topic) {
                    self.state = SubscriptionStateChange::Change {
                        add: vec![],
                        remove: vec![topic.to_string()],
                    };
                }
            }
        }

        subscribed.remove(topic);
    }

    /// Stop following a server's member events. Takes effect on the next
    /// `apply_state`, which runs before the listener reads another event;
    /// safe in the `Reset` state.
    pub fn remove_member_topic(&mut self, server_id: &str) {
        let topic = member_topic(server_id);
        self.member_topics.remove(&topic);
        self.member_topic_removals.insert(topic);
    }

    /// Clone the active user
    pub fn clone_user(&self) -> User {
        self.cache.users.get(&self.cache.user_id).unwrap().clone()
    }

    /// Reset the current state
    pub async fn reset_state(&mut self) {
        self.state = SubscriptionStateChange::Reset;
        let mut subscribed = self.subscribed.write().await;
        subscribed.clear();

        // Re-derived from the server cache by the next `apply_state`
        self.member_topics.clear();
        self.member_topic_removals.clear();

        // Nothing re-derives the session topic from servers / channels /
        // users, so it is pinned here rather than by the caller. Bots
        // (empty session id) never get one, same as in `State::from`.
        if !self.session_id.is_empty() {
            subscribed.insert(session_topic(&self.session_id));
        }
    }

    /// Add a new subscription
    pub async fn insert_subscription(&mut self, subscription: String) {
        let mut subscribed = self.subscribed.write().await;
        if subscribed.contains(&subscription) {
            return;
        }

        match &mut self.state {
            SubscriptionStateChange::None => {
                self.state = SubscriptionStateChange::Change {
                    add: vec![subscription.clone()],
                    remove: vec![],
                };
            }
            SubscriptionStateChange::Change { add, .. } => {
                add.push(subscription.clone());
            }
            SubscriptionStateChange::Reset => {}
        }

        subscribed.insert(subscription);
    }

    /// Remove existing subscription
    pub async fn remove_subscription(&mut self, subscription: &str) {
        let mut subscribed = self.subscribed.write().await;
        if !subscribed.contains(&subscription.to_string()) {
            return;
        }

        match &mut self.state {
            SubscriptionStateChange::None => {
                self.state = SubscriptionStateChange::Change {
                    add: vec![],
                    remove: vec![subscription.to_string()],
                };
            }
            SubscriptionStateChange::Change { remove, .. } => {
                remove.push(subscription.to_string());
            }
            SubscriptionStateChange::Reset => panic!("Should not remove during a reset!"),
        }

        subscribed.remove(subscription);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        time::{Duration, Instant},
    };

    use revolt_database::{events::client::session_topic, Server, User};

    use super::{is_ulid_shaped, ActiveServers, State, SubscriptionStateChange};

    fn user(id: &str) -> User {
        User {
            id: id.to_string(),
            username: "user".to_string(),
            ..Default::default()
        }
    }

    /// A new connection listens on its own session topic from the start,
    /// and not on any other session's topic.
    #[tokio::test]
    async fn new_state_subscribes_own_session_topic() {
        let state = State::from(user("01USER0000000000000000000A"), "01SESSIONA".to_string());
        let subscribed = state.subscribed.read().await;

        assert!(subscribed.contains(&session_topic("01SESSIONA")));
        assert!(!subscribed.contains(&session_topic("01SESSIONB")));
        assert!(subscribed.contains("01USER0000000000000000000A!"));
        assert!(subscribed.contains("01USER0000000000000000000A"));
    }

    /// Ready generation resets and rebuilds subscriptions from servers,
    /// channels and users; the session topic must survive that reset and
    /// be part of the set the listener subscribes on `Reset`.
    #[tokio::test]
    async fn session_topic_survives_reset() {
        let mut state = State::from(user("01USER0000000000000000000A"), "01SESSIONA".to_string());

        state.reset_state().await;
        state.insert_subscription(state.private_topic.clone()).await;
        state
            .insert_subscription("01CHANNEL000000000000000000".to_string())
            .await;

        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Reset
        ));
        assert!(state
            .subscribed
            .read()
            .await
            .contains(&session_topic("01SESSIONA")));

        // Later incremental changes leave it in place.
        state
            .remove_subscription("01CHANNEL000000000000000000")
            .await;
        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Change { .. }
        ));
        assert!(state
            .subscribed
            .read()
            .await
            .contains(&session_topic("01SESSIONA")));
    }

    /// Bots connect with an empty session id. They must not listen on a
    /// `session:` topic at all, neither at connect nor after a reset.
    #[tokio::test]
    async fn empty_session_id_subscribes_no_session_topic() {
        let mut state = State::from(user("01BOT00000000000000000000A"), String::new());
        let prefix = session_topic("");

        {
            let subscribed = state.subscribed.read().await;
            assert!(!subscribed.iter().any(|t| t.starts_with(&prefix)));
            assert!(subscribed.contains("01BOT00000000000000000000A!"));
        }

        state.reset_state().await;
        assert!(!state
            .subscribed
            .read()
            .await
            .iter()
            .any(|t| t.starts_with(&prefix)));

        state.insert_subscription(state.private_topic.clone()).await;
        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Reset
        ));
        assert!(!state
            .subscribed
            .read()
            .await
            .iter()
            .any(|t| t.starts_with(&prefix)));
    }

    const USER_ID: &str = "01USER0000000000000000000A";

    fn server_id(n: usize) -> String {
        format!("01J{n:023}")
    }

    fn server(id: &str) -> Server {
        Server {
            id: id.to_string(),
            owner: "01J00000000000000000000OWN".to_string(),
            name: "server".to_string(),
            description: None,
            channels: vec![],
            categories: None,
            system_messages: None,
            roles: HashMap::new(),
            default_permissions: 0,
            icon: None,
            banner: None,
            flags: None,
            nsfw: false,
            analytics: false,
            discoverable: false,
            discovery_requested: false,
            voice_region: None,
            boost_count: None,
            boost_tier: None,
            afk_channel_id: None,
            afk_timeout: None,
        }
    }

    /// A user state past its initial `Reset`, member of `servers`
    async fn member_state(servers: &[&str]) -> State {
        let mut state = State::from(user(USER_ID), "01SESSIONA".to_string());
        for id in servers {
            state.cache.servers.insert(id.to_string(), server(id));
        }
        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Reset
        ));
        state
    }

    async fn touch(state: &State, id: &str) {
        state
            .active_servers
            .lock()
            .await
            .touch(id.to_string(), Instant::now());
    }

    async fn is_subscribed(state: &State, topic: &str) -> bool {
        state.subscribed.read().await.contains(topic)
    }

    async fn member_topic_count(state: &State) -> usize {
        state
            .subscribed
            .read()
            .await
            .iter()
            .filter(|t| t.ends_with('u'))
            .count()
    }

    fn removed(change: SubscriptionStateChange) -> Vec<String> {
        match change {
            SubscriptionStateChange::Change { remove, .. } => remove,
            _ => vec![],
        }
    }

    #[test]
    fn sec007_touch_evicts_least_recently_touched() {
        let now = Instant::now();
        let mut servers = ActiveServers::new(2, Duration::from_secs(900));

        assert_eq!(servers.touch("A".to_string(), now), None);
        assert_eq!(servers.touch("B".to_string(), now), None);
        // Refreshing an existing key evicts nothing and makes it recent.
        assert_eq!(servers.touch("A".to_string(), now), None);
        assert_eq!(servers.touch("C".to_string(), now), Some("B".to_string()));

        assert!(!servers.contains("B"));
        assert_eq!(
            servers.live_keys(now),
            vec!["A".to_string(), "C".to_string()]
        );
    }

    #[test]
    fn sec007_live_keys_expire_without_refresh() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut servers = ActiveServers::new(5, ttl);
        servers.touch("A".to_string(), start);

        // Reading must not push the expiry back.
        assert_eq!(servers.live_keys(start + Duration::from_secs(5)), vec!["A"]);
        assert_eq!(servers.live_keys(start + Duration::from_secs(9)), vec!["A"]);
        assert!(servers.live_keys(start + ttl).is_empty());
        assert!(!servers.contains("A"));
    }

    #[test]
    fn sec007_remove_drops_key() {
        let now = Instant::now();
        let mut servers = ActiveServers::new(5, Duration::from_secs(900));
        servers.touch("A".to_string(), now);
        servers.touch("B".to_string(), now);

        assert!(servers.remove("A"));
        assert!(!servers.remove("A"));
        assert!(!servers.remove("Z"));
        assert_eq!(servers.live_keys(now), vec!["B"]);
    }

    #[test]
    fn sec007_ulid_shape_table() {
        for id in [
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "7ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "00000000000000000000000000",
            server_id(42).as_str(),
        ] {
            assert!(is_ulid_shaped(id), "{id} should be accepted");
        }

        for id in [
            "",
            "01ARZ3NDEKTSV4RRFFQ69G5FA",
            "01ARZ3NDEKTSV4RRFFQ69G5FAVV",
            "01arz3ndektsv4rrffq69g5fav",
            "01ARZ3NDEKTSV4RRFFQ69G5FAI",
            "01ARZ3NDEKTSV4RRFFQ69G5FAL",
            "01ARZ3NDEKTSV4RRFFQ69G5FAO",
            "01ARZ3NDEKTSV4RRFFQ69G5FAU",
            "01ARZ3NDEKTSV4RRFFQ69G5FA!",
            "01ARZ3NDEKTSV4RRFFQ69G5FAu",
            "01ARZ3NDEKTSV4RRFFQ69G5F\u{c9}",
            "session:01ARZ3NDEKTSV4RRFF",
        ] {
            assert!(!is_ulid_shaped(id), "{id:?} should be refused");
        }
    }

    /// `Subscribe` for a server the user is not in yields no member topic.
    #[tokio::test]
    async fn sec007_non_member_server_gets_no_member_topic() {
        let member = server_id(1);
        let stranger = server_id(2);
        let mut state = member_state(&[&member]).await;

        touch(&state, &stranger).await;
        touch(&state, &member).await;
        state.apply_state().await;

        assert!(is_subscribed(&state, &format!("{member}u")).await);
        assert!(!is_subscribed(&state, &format!("{stranger}u")).await);
        assert_eq!(member_topic_count(&state).await, 1);
    }

    /// Leaving (or being kicked / banned from) a server drops its member
    /// topic, and the listener is told to unsubscribe it.
    #[tokio::test]
    async fn sec007_leave_drops_member_topic() {
        let s = server_id(1);
        let mut state = member_state(&[&s]).await;

        touch(&state, &s).await;
        state.apply_state().await;
        assert!(is_subscribed(&state, &format!("{s}u")).await);

        state.cache.servers.remove(&s);
        let change = state.apply_state().await;

        assert_eq!(removed(change), vec![format!("{s}u")]);
        assert!(!is_subscribed(&state, &format!("{s}u")).await);
        assert!(state.member_topics.is_empty());
    }

    /// Evicting a server from the bounded set unsubscribes it; it cannot
    /// linger until after a ban.
    #[tokio::test]
    async fn sec007_evicted_then_banned_keeps_no_member_topic() {
        let s = server_id(0);
        let others: Vec<String> = (1..=5).map(server_id).collect();
        let mut all: Vec<&str> = vec![&s];
        all.extend(others.iter().map(String::as_str));
        let mut state = member_state(&all).await;

        touch(&state, &s).await;
        state.apply_state().await;
        assert!(is_subscribed(&state, &format!("{s}u")).await);

        for other in &others {
            touch(&state, other).await;
            state.apply_state().await;
        }

        state.cache.servers.remove(&s);
        state.apply_state().await;

        assert!(!is_subscribed(&state, &format!("{s}u")).await);
        assert_eq!(member_topic_count(&state).await, 5);
    }

    /// Fifty member servers subscribed one after another still leave at
    /// most five member topics, the five most recent.
    #[tokio::test]
    async fn sec007_member_topics_stay_bounded() {
        let ids: Vec<String> = (0..50).map(server_id).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let mut state = member_state(&refs).await;

        for id in &ids {
            touch(&state, id).await;
            state.apply_state().await;
            assert!(member_topic_count(&state).await <= 5);
        }

        assert_eq!(member_topic_count(&state).await, 5);
        for id in &ids[45..] {
            assert!(is_subscribed(&state, &format!("{id}u")).await);
        }
    }

    /// An entry past its TTL stops yielding a topic; one about to expire
    /// still does.
    #[tokio::test]
    async fn sec007_expired_server_drops_member_topic() {
        let s = server_id(1);
        let mut state = member_state(&[&s]).await;

        touch(&state, &s).await;
        state.apply_state().await;
        assert!(is_subscribed(&state, &format!("{s}u")).await);

        let long_ago = Instant::now()
            .checked_sub(Duration::from_secs(901))
            .expect("monotonic clock older than the TTL");
        state.active_servers.lock().await.touch(s.clone(), long_ago);
        let change = state.apply_state().await;

        assert_eq!(removed(change), vec![format!("{s}u")]);
        assert!(!state.active_servers.lock().await.contains(&s));
    }

    /// Bots follow every server they are in, without `Subscribe`, and
    /// stop when they leave or are removed. A topic already subscribed by
    /// the Ready path is adopted, not subscribed twice.
    #[tokio::test]
    async fn sec007_bot_member_topics_follow_server_cache() {
        let a = server_id(1);
        let b = server_id(2);
        let mut state = State::from(user("01J000000000000000000000B0"), String::new());
        state.cache.is_bot = true;
        state.cache.servers.insert(a.clone(), server(&a));
        state.cache.servers.insert(b.clone(), server(&b));
        state.insert_subscription(format!("{a}u")).await;

        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Reset
        ));
        assert!(is_subscribed(&state, &format!("{a}u")).await);
        assert!(is_subscribed(&state, &format!("{b}u")).await);
        assert!(state.member_topics.contains(&format!("{a}u")));

        state.cache.servers.remove(&a);
        let change = state.apply_state().await;

        assert_eq!(removed(change), vec![format!("{a}u")]);
        assert!(!is_subscribed(&state, &format!("{a}u")).await);
        assert!(is_subscribed(&state, &format!("{b}u")).await);

        // Same server count, different servers.
        let c = server_id(3);
        state.cache.servers.remove(&b);
        state.cache.servers.insert(c.clone(), server(&c));
        state.apply_state().await;

        assert!(!is_subscribed(&state, &format!("{b}u")).await);
        assert!(is_subscribed(&state, &format!("{c}u")).await);
        assert_eq!(member_topic_count(&state).await, 1);
    }

    /// A reset forgets the member topics; the next flush rebuilds them as
    /// part of the full set the listener subscribes.
    #[tokio::test]
    async fn sec007_reset_rebuilds_member_topics() {
        let s = server_id(1);
        let mut state = member_state(&[&s]).await;

        touch(&state, &s).await;
        state.apply_state().await;
        assert!(state.member_topics.contains(&format!("{s}u")));

        state.reset_state().await;
        assert!(state.member_topics.is_empty());
        assert!(!is_subscribed(&state, &format!("{s}u")).await);

        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Reset
        ));
        assert!(is_subscribed(&state, &format!("{s}u")).await);
        assert!(state.member_topics.contains(&format!("{s}u")));
    }

    /// `remove_member_topic` unsubscribes on the next flush and does not
    /// panic in the `Reset` state.
    #[tokio::test]
    async fn sec007_remove_member_topic() {
        let s = server_id(1);
        let mut state = member_state(&[&s]).await;

        touch(&state, &s).await;
        state.apply_state().await;

        state.active_servers.lock().await.remove(&s);
        state.remove_member_topic(&s);
        let change = state.apply_state().await;
        assert_eq!(removed(change), vec![format!("{s}u")]);
        assert!(!is_subscribed(&state, &format!("{s}u")).await);

        touch(&state, &s).await;
        state.apply_state().await;
        state.reset_state().await;
        state.remove_member_topic(&s);
        state.active_servers.lock().await.remove(&s);
        assert!(matches!(
            state.apply_state().await,
            SubscriptionStateChange::Reset
        ));
        assert!(!is_subscribed(&state, &format!("{s}u")).await);
    }
}
