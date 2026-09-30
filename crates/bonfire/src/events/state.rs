use std::{
    collections::{HashMap, HashSet}, num::NonZeroUsize, sync::Arc, time::Duration
};

use tokio::sync::{Mutex, RwLock};
use lru::LruCache;
use lru_time_cache::{LruCache as LruTimeCache, TimedEntry};
use revolt_database::{events::client::session_topic, Channel, Member, Server, User};

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
    pub active_servers: Arc<Mutex<LruTimeCache<String, ()>>>,
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
            active_servers: Arc::new(Mutex::new(LruTimeCache::with_expiry_duration_and_capacity(
                Duration::from_secs(900),
                5,
            ))),
            session_id,
            private_topic,
            state: SubscriptionStateChange::Reset,
        }
    }

    /// Apply currently queued state
    pub async fn apply_state(&mut self) -> SubscriptionStateChange {
        // Check if we need to change subscriptions to member event topics
        if !self.cache.is_bot {
            enum Server {
                Subscribe(String),
                Unsubscribe(String),
            }

            let active_server_changes: Vec<Server> = {
                let mut active_servers = self.active_servers.lock().await;
                active_servers
                    .notify_iter()
                    .map(|e| match e {
                        TimedEntry::Valid(k, _) => Server::Subscribe(format!("{}u", k)),
                        TimedEntry::Expired(k, _) => Server::Unsubscribe(format!("{}u", k)),
                    })
                    .collect()
                // It is bad practice to open more than one Mutex at once and could
                // lead to a deadlock, so instead we choose to collect the changes.
            };

            for entry in active_server_changes {
                match entry {
                    Server::Subscribe(k) => {
                        self.insert_subscription(k).await;
                    }
                    Server::Unsubscribe(k) => {
                        self.remove_subscription(&k).await;
                    }
                }
            }
        }

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

    /// Clone the active user
    pub fn clone_user(&self) -> User {
        self.cache.users.get(&self.cache.user_id).unwrap().clone()
    }

    /// Reset the current state
    pub async fn reset_state(&mut self) {
        self.state = SubscriptionStateChange::Reset;
        let mut subscribed = self.subscribed.write().await;
        subscribed.clear();

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
    use revolt_database::{events::client::session_topic, User};

    use super::{State, SubscriptionStateChange};

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
}
