//! Response cache: Redis (`gamedata:v1:<kind>:<id>`, JSON, SET EX) shared
//! by every service, fronted by an in-process cache that also stands in
//! when Redis is unreachable. A cache hit costs no budget.

use std::time::Duration;

use moka::sync::Cache;
use redis_kiss::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};

use crate::GameData;

/// How long a cached value lives
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ttl {
    OneHour,
    SixHours,
    OneDay,
}

impl Ttl {
    pub(crate) fn secs(self) -> u64 {
        match self {
            Ttl::OneHour => 60 * 60,
            Ttl::SixHours => 6 * 60 * 60,
            Ttl::OneDay => 24 * 60 * 60,
        }
    }
}

/// In-process caches, one per lifetime
pub(crate) struct Caches {
    one_hour: Cache<String, String>,
    six_hours: Cache<String, String>,
    one_day: Cache<String, String>,
}

fn local(ttl: Ttl) -> Cache<String, String> {
    Cache::builder()
        .max_capacity(10_000)
        .time_to_live(Duration::from_secs(ttl.secs()))
        .build()
}

impl Caches {
    pub(crate) fn new() -> Caches {
        Caches {
            one_hour: local(Ttl::OneHour),
            six_hours: local(Ttl::SixHours),
            one_day: local(Ttl::OneDay),
        }
    }

    fn of(&self, ttl: Ttl) -> &Cache<String, String> {
        match ttl {
            Ttl::OneHour => &self.one_hour,
            Ttl::SixHours => &self.six_hours,
            Ttl::OneDay => &self.one_day,
        }
    }
}

/// Redis operations give up after this long
const REDIS_TIMEOUT: Duration = Duration::from_secs(1);

async fn redis_get(key: &str) -> Option<String> {
    let work = async {
        let mut conn = redis_kiss::get_connection().await.ok()?;
        conn.get::<_, Option<String>>(key).await.ok()?
    };
    tokio::time::timeout(REDIS_TIMEOUT, work).await.ok().flatten()
}

async fn redis_set(key: &str, value: &str, ttl: Ttl) {
    let work = async {
        let mut conn = redis_kiss::get_connection().await.ok()?;
        conn.set_ex::<_, _, ()>(key, value, ttl.secs() as usize)
            .await
            .ok()
    };
    if tokio::time::timeout(REDIS_TIMEOUT, work)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        log::debug!("gamedata: could not write {key} to Redis");
    }
}

impl GameData {
    /// Cached value under `key`, if any (an unreadable value is a miss)
    pub(crate) async fn cache_get<T: DeserializeOwned>(&self, key: &str, ttl: Ttl) -> Option<T> {
        let local = self.cache.of(ttl);
        if let Some(raw) = local.get(key) {
            if let Ok(value) = serde_json::from_str(&raw) {
                return Some(value);
            }
            local.invalidate(key);
        }

        if self.redis {
            let raw = redis_get(key).await?;
            let value = serde_json::from_str(&raw).ok()?;
            local.insert(key.to_string(), raw);
            return Some(value);
        }
        None
    }

    /// Cache `value` under `key` for `ttl`
    pub(crate) async fn cache_put<T: Serialize>(&self, key: &str, ttl: Ttl, value: &T) {
        let Ok(raw) = serde_json::to_string(value) else {
            return;
        };
        if self.redis {
            redis_set(key, &raw, ttl).await;
        }
        self.cache.of(ttl).insert(key.to_string(), raw);
    }
}
