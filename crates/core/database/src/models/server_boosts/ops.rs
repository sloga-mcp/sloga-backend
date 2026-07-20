pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::ServerBoost;

#[async_trait]
pub trait AbstractServerBoosts: Sync + Send {
    /// Insert a new boost slot
    async fn insert_server_boost(&self, boost: &ServerBoost) -> Result<()>;

    /// Fetch a boost slot by id
    async fn fetch_server_boost(&self, id: &str) -> Result<ServerBoost>;

    /// Fetch every slot a user owns (allocated or not, expired included —
    /// callers filter; the inventory view wants to show expiring slots)
    async fn fetch_server_boosts_by_user(&self, user_id: &str) -> Result<Vec<ServerBoost>>;

    /// Fetch every slot allocated to a server (expired included — callers filter)
    async fn fetch_server_boosts_by_server(&self, server_id: &str) -> Result<Vec<ServerBoost>>;

    /// Count unexpired slots allocated to a server
    async fn count_server_boosts_by_server(&self, server_id: &str, now_ms: i64) -> Result<u64>;

    /// Count a user's unexpired, unallocated slots
    async fn count_unallocated_server_boosts(&self, user_id: &str, now_ms: i64) -> Result<u64>;

    /// Atomically claim up to `count` of a user's unallocated, unexpired
    /// slots for a server; returns the claimed slot ids (may be fewer than
    /// requested if a concurrent request raced — the caller rolls back via
    /// `deallocate_server_boosts_by_ids`)
    async fn allocate_server_boosts(
        &self,
        user_id: &str,
        server_id: &str,
        count: u32,
        now_ms: i64,
    ) -> Result<Vec<String>>;

    /// Return up to `count` (None = all) of a user's slots on a server to
    /// their inventory; returns how many were freed
    async fn deallocate_server_boosts(
        &self,
        user_id: &str,
        server_id: &str,
        count: Option<u32>,
    ) -> Result<u64>;

    /// Return specific slots to their owners' inventories (allocation rollback)
    async fn deallocate_server_boosts_by_ids(&self, ids: &[String]) -> Result<()>;

    /// Server-deletion cascade: free every slot allocated to the server
    async fn deallocate_all_server_boosts_for_server(&self, server_id: &str) -> Result<u64>;

    /// Account-deletion cascade: delete every slot a user owns; returns the
    /// distinct server ids that held allocations (for recounts)
    async fn delete_server_boosts_by_user(&self, user_id: &str) -> Result<Vec<String>>;

    /// Delete a single slot (privileged revoke)
    async fn delete_server_boost(&self, id: &str) -> Result<()>;

    /// Delete every expired slot, returning what was removed (callers
    /// recount the affected servers)
    async fn delete_expired_server_boosts(&self, now_ms: i64) -> Result<Vec<ServerBoost>>;

    /// Distinct server ids that currently appear in any slot's allocation
    /// (crond self-heal recount scan)
    async fn fetch_boosted_server_ids(&self) -> Result<Vec<String>>;
}
