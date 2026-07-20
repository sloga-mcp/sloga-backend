use revolt_result::Result;

use crate::{Database, PartialServer};

auto_derived!(
    /// Where a boost slot came from. Only `AdminGrant` is minted in v1;
    /// `Purchase`/`Subscription` are reserved for the future billing
    /// integration so its rows need no migration.
    pub enum BoostSource {
        AdminGrant,
        Purchase,
        Subscription,
    }

    /// Server boost slot — owned by a user, optionally allocated to a server.
    ///
    /// `server_id: None` (stored as an ABSENT field — mind `$exists` in Mongo
    /// queries) means the slot sits unallocated in the owner's inventory.
    /// Timestamps are epoch milliseconds (iso8601 timestamps are
    /// inconsistently serialised in this DB — see prune_large_attachments).
    pub struct ServerBoost {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Slot owner
        pub user_id: String,
        /// Server this slot is currently applied to, if any
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server_id: Option<String>,
        /// How this slot entered the system
        pub source: BoostSource,
        /// Epoch ms after which this slot no longer counts and is pruned;
        /// absent = permanent
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<i64>,
        /// Epoch ms of the current allocation (future move-cooldown hook)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub allocated_at: Option<i64>,
    }
);

/// Current epoch milliseconds
pub fn boost_now_ms() -> i64 {
    iso8601_timestamp::Timestamp::now_utc()
        .duration_since(iso8601_timestamp::Timestamp::UNIX_EPOCH)
        .whole_milliseconds() as i64
}

#[allow(clippy::disallowed_methods)]
impl ServerBoost {
    /// Whether this slot is expired at the given instant
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at.is_some_and(|at| at <= now_ms)
    }

    /// Mint `count` admin-granted slots for a user (privileged mint path;
    /// the future billing webhook mints Purchase/Subscription slots the
    /// same way).
    pub async fn create_granted(
        db: &Database,
        user_id: &str,
        count: u32,
        expires_at: Option<i64>,
    ) -> Result<Vec<ServerBoost>> {
        let mut minted = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let boost = ServerBoost {
                id: ulid::Ulid::new().to_string(),
                user_id: user_id.to_string(),
                server_id: None,
                source: BoostSource::AdminGrant,
                expires_at,
                allocated_at: None,
            };
            db.insert_server_boost(&boost).await?;
            minted.push(boost);
        }
        Ok(minted)
    }

    /// Authoritative recount of a server's boost count + tier.
    ///
    /// Called after EVERY boost mutation (allocate, deallocate, revoke,
    /// expiry prune, cascades) instead of incremental `$inc` bookkeeping:
    /// races collapse to last-write-wins over a recount, and threshold
    /// config changes self-heal on the next mutation or crond pass.
    ///
    /// Tolerates a missing server (deleted → nothing to recount) and skips
    /// the write entirely when nothing changed, so the crond self-heal pass
    /// doesn't spam ServerUpdate events.
    pub async fn recount_for_server(db: &Database, server_id: &str) -> Result<()> {
        let mut server = match db.fetch_server(server_id).await {
            Ok(server) => server,
            // Deleted server — nothing to recount. Any OTHER error must
            // propagate: swallowing a transient fetch failure here is how a
            // stale tier would get stranded past the self-heal sweep.
            Err(error) if matches!(error.error_type, revolt_result::ErrorType::NotFound) => {
                return Ok(())
            }
            Err(error) => return Err(error),
        };

        let config = revolt_config::config().await;
        let count = db
            .count_server_boosts_by_server(server_id, boost_now_ms())
            .await? as u32;
        let tier = config.features.boosts.tier_for(count);

        if server.boost_count.unwrap_or(0) == count as i32
            && server.boost_tier.unwrap_or(0) == tier as i32
        {
            return Ok(());
        }

        server
            .update(
                db,
                PartialServer {
                    boost_count: Some(count as i32),
                    boost_tier: Some(tier as i32),
                    ..Default::default()
                },
                vec![],
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::ServerBoost;

    #[tokio::test]
    async fn boost_slot_lifecycle() {
        database_test!(|db| async move {
            // Mint 3 permanent slots + 1 already-expired slot
            let minted = ServerBoost::create_granted(&db, "user_a", 3, None)
                .await
                .unwrap();
            assert_eq!(minted.len(), 3);
            ServerBoost::create_granted(&db, "user_a", 1, Some(1))
                .await
                .unwrap();

            let now = 1_000_000;

            // Expired slot is excluded from both counts
            assert_eq!(
                db.count_unallocated_server_boosts("user_a", now)
                    .await
                    .unwrap(),
                3
            );

            // Claim 2 for a server — expired slot must never be spendable
            let claimed = db
                .allocate_server_boosts("user_a", "server_1", 2, now)
                .await
                .unwrap();
            assert_eq!(claimed.len(), 2);
            assert_eq!(
                db.count_server_boosts_by_server("server_1", now)
                    .await
                    .unwrap(),
                2
            );
            assert_eq!(
                db.count_unallocated_server_boosts("user_a", now)
                    .await
                    .unwrap(),
                1
            );

            // Over-ask claims only what exists (route rolls back on this)
            let partial = db
                .allocate_server_boosts("user_a", "server_2", 5, now)
                .await
                .unwrap();
            assert_eq!(partial.len(), 1);
            db.deallocate_server_boosts_by_ids(&partial).await.unwrap();
            assert_eq!(
                db.count_unallocated_server_boosts("user_a", now)
                    .await
                    .unwrap(),
                1
            );

            // Deallocate one from server_1
            assert_eq!(
                db.deallocate_server_boosts("user_a", "server_1", Some(1))
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                db.count_server_boosts_by_server("server_1", now)
                    .await
                    .unwrap(),
                1
            );

            // Another user's dealloc can never touch user_a's slots
            assert_eq!(
                db.deallocate_server_boosts("user_b", "server_1", None)
                    .await
                    .unwrap(),
                0
            );

            // Expiry sweep removes exactly the expired slot
            let removed = db.delete_expired_server_boosts(now).await.unwrap();
            assert_eq!(removed.len(), 1);
            assert!(removed[0].expires_at.is_some());

            // Server-delete cascade frees the remaining allocation
            assert_eq!(
                db.deallocate_all_server_boosts_for_server("server_1")
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                db.count_unallocated_server_boosts("user_a", now)
                    .await
                    .unwrap(),
                3
            );

            // Account-delete cascade reports affected servers
            let claimed = db
                .allocate_server_boosts("user_a", "server_3", 1, now)
                .await
                .unwrap();
            assert_eq!(claimed.len(), 1);
            let affected = db.delete_server_boosts_by_user("user_a").await.unwrap();
            assert_eq!(affected, vec!["server_3".to_string()]);
            assert_eq!(
                db.count_unallocated_server_boosts("user_a", now)
                    .await
                    .unwrap(),
                0
            );
        });
    }
}
