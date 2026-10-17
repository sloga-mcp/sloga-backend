//! Upstream call budgets
//!
//! Fixed windows counted in Redis (`gamedata:budget:<source>:<pool>:<window>`,
//! INCR + EXPIRE in one MULTI) so every service draws from the same pool.
//! When Redis is unreachable, or in tests, each process counts on its own.

use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{GameData, GameDataError, Pool, Result};

/// Which budget an upstream call draws on
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Budget {
    /// Steam store `appdetails` + `storesearch`, split by pool
    SteamStore(Pool),
    /// Steam news (`api.steampowered.com`)
    SteamNews,
    /// Blizzard API, one budget for every pool
    Blizzard,
}

/// A budget's Redis key stem, limit and window length
pub(crate) struct BudgetSpec {
    pub(crate) stem: &'static str,
    pub(crate) limit: u32,
    pub(crate) window_secs: u64,
}

/// In-process counters: key stem -> (window index, calls in that window)
#[derive(Default)]
pub(crate) struct LocalBudgets {
    counters: HashMap<&'static str, (u64, u32)>,
}

impl LocalBudgets {
    /// Count one call in `window`; false once `limit` calls were counted
    pub(crate) fn take(&mut self, stem: &'static str, window: u64, limit: u32) -> bool {
        let entry = self.counters.entry(stem).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// INCR the window key (setting its expiry); `None` when Redis is
/// unreachable or slow
async fn redis_count(key: &str, ttl_secs: u64) -> Option<u64> {
    let work = async {
        let mut conn = redis_kiss::get_connection().await.ok()?;
        let (count, ()): (u64, ()) = redis_kiss::redis::pipe()
            .atomic()
            .incr(key, 1u64)
            .expire(key, ttl_secs as usize)
            .query_async(&mut *conn)
            .await
            .ok()?;
        Some(count)
    };
    tokio::time::timeout(Duration::from_secs(1), work)
        .await
        .ok()
        .flatten()
}

impl GameData {
    pub(crate) fn budget_spec(&self, budget: Budget) -> BudgetSpec {
        let cfg = &self.config;
        let store_window = cfg.steam_store_window_secs.max(1);
        match budget {
            Budget::SteamStore(pool) => BudgetSpec {
                stem: match pool {
                    Pool::Embed => "steam_store:embed",
                    Pool::Interactive => "steam_store:interactive",
                },
                limit: match pool {
                    Pool::Embed => cfg.steam_store_embed_budget,
                    Pool::Interactive => cfg.steam_store_interactive_budget,
                },
                window_secs: store_window,
            },
            Budget::SteamNews => BudgetSpec {
                stem: "steam_news:shared",
                limit: cfg.steam_news_per_window,
                window_secs: store_window,
            },
            Budget::Blizzard => BudgetSpec {
                stem: "blizzard:shared",
                limit: cfg.blizzard_per_second,
                window_secs: 1,
            },
        }
    }

    /// Spend one call of `budget` at time `now` (seconds since the epoch)
    pub(crate) async fn take_budget_at(&self, budget: Budget, now: u64) -> Result<()> {
        let spec = self.budget_spec(budget);
        if spec.limit == 0 {
            return Err(GameDataError::Budget);
        }
        let window = now / spec.window_secs;

        if self.redis {
            let key = format!("gamedata:budget:{}:{window}", spec.stem);
            if let Some(count) = redis_count(&key, spec.window_secs + 5).await {
                return if count <= u64::from(spec.limit) {
                    Ok(())
                } else {
                    Err(GameDataError::Budget)
                };
            }
            log::debug!("gamedata: Redis unavailable, counting {} in-process", spec.stem);
        }

        let allowed = self
            .budgets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take(spec.stem, window, spec.limit);
        if allowed {
            Ok(())
        } else {
            Err(GameDataError::Budget)
        }
    }

    /// Spend one call of `budget` now; `Budget` when it is empty
    pub(crate) async fn take_budget(&self, budget: Budget) -> Result<()> {
        self.take_budget_at(budget, now_secs()).await
    }
}
