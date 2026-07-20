use revolt_result::Result;

use crate::ReferenceDb;
use crate::ServerBoost;

use super::AbstractServerBoosts;

fn is_unexpired(boost: &ServerBoost, now_ms: i64) -> bool {
    !boost.is_expired(now_ms)
}

#[async_trait]
impl AbstractServerBoosts for ReferenceDb {
    async fn insert_server_boost(&self, boost: &ServerBoost) -> Result<()> {
        let mut boosts = self.server_boosts.lock().await;
        if boosts.contains_key(&boost.id) {
            Err(create_database_error!("insert", "server_boost"))
        } else {
            boosts.insert(boost.id.clone(), boost.clone());
            Ok(())
        }
    }

    async fn fetch_server_boost(&self, id: &str) -> Result<ServerBoost> {
        let boosts = self.server_boosts.lock().await;
        boosts
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_server_boosts_by_user(&self, user_id: &str) -> Result<Vec<ServerBoost>> {
        let boosts = self.server_boosts.lock().await;
        Ok(boosts
            .values()
            .filter(|b| b.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn fetch_server_boosts_by_server(&self, server_id: &str) -> Result<Vec<ServerBoost>> {
        let boosts = self.server_boosts.lock().await;
        Ok(boosts
            .values()
            .filter(|b| b.server_id.as_deref() == Some(server_id))
            .cloned()
            .collect())
    }

    async fn count_server_boosts_by_server(&self, server_id: &str, now_ms: i64) -> Result<u64> {
        let boosts = self.server_boosts.lock().await;
        Ok(boosts
            .values()
            .filter(|b| b.server_id.as_deref() == Some(server_id) && is_unexpired(b, now_ms))
            .count() as u64)
    }

    async fn count_unallocated_server_boosts(&self, user_id: &str, now_ms: i64) -> Result<u64> {
        let boosts = self.server_boosts.lock().await;
        Ok(boosts
            .values()
            .filter(|b| b.user_id == user_id && b.server_id.is_none() && is_unexpired(b, now_ms))
            .count() as u64)
    }

    async fn allocate_server_boosts(
        &self,
        user_id: &str,
        server_id: &str,
        count: u32,
        now_ms: i64,
    ) -> Result<Vec<String>> {
        let mut boosts = self.server_boosts.lock().await;

        // Deterministic claim order (oldest slot first) so tests are stable.
        let mut candidates: Vec<String> = boosts
            .values()
            .filter(|b| b.user_id == user_id && b.server_id.is_none() && is_unexpired(b, now_ms))
            .map(|b| b.id.clone())
            .collect();
        candidates.sort();

        let mut claimed = Vec::new();
        for id in candidates.into_iter().take(count as usize) {
            if let Some(boost) = boosts.get_mut(&id) {
                boost.server_id = Some(server_id.to_string());
                boost.allocated_at = Some(now_ms);
                claimed.push(id);
            }
        }

        Ok(claimed)
    }

    async fn deallocate_server_boosts(
        &self,
        user_id: &str,
        server_id: &str,
        count: Option<u32>,
    ) -> Result<u64> {
        let mut boosts = self.server_boosts.lock().await;

        let mut targets: Vec<String> = boosts
            .values()
            .filter(|b| b.user_id == user_id && b.server_id.as_deref() == Some(server_id))
            .map(|b| b.id.clone())
            .collect();
        targets.sort();
        if let Some(count) = count {
            targets.truncate(count as usize);
        }

        let mut freed = 0;
        for id in targets {
            if let Some(boost) = boosts.get_mut(&id) {
                boost.server_id = None;
                boost.allocated_at = None;
                freed += 1;
            }
        }

        Ok(freed)
    }

    async fn deallocate_server_boosts_by_ids(&self, ids: &[String]) -> Result<()> {
        let mut boosts = self.server_boosts.lock().await;
        for id in ids {
            if let Some(boost) = boosts.get_mut(id) {
                boost.server_id = None;
                boost.allocated_at = None;
            }
        }
        Ok(())
    }

    async fn deallocate_all_server_boosts_for_server(&self, server_id: &str) -> Result<u64> {
        let mut boosts = self.server_boosts.lock().await;
        let mut freed = 0;
        for boost in boosts.values_mut() {
            if boost.server_id.as_deref() == Some(server_id) {
                boost.server_id = None;
                boost.allocated_at = None;
                freed += 1;
            }
        }
        Ok(freed)
    }

    async fn delete_server_boosts_by_user(&self, user_id: &str) -> Result<Vec<String>> {
        let mut boosts = self.server_boosts.lock().await;

        let mut affected: Vec<String> = boosts
            .values()
            .filter(|b| b.user_id == user_id)
            .filter_map(|b| b.server_id.clone())
            .collect();
        affected.sort();
        affected.dedup();

        boosts.retain(|_, b| b.user_id != user_id);
        Ok(affected)
    }

    async fn delete_server_boost(&self, id: &str) -> Result<()> {
        let mut boosts = self.server_boosts.lock().await;
        if boosts.remove(id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_expired_server_boosts(&self, now_ms: i64) -> Result<Vec<ServerBoost>> {
        let mut boosts = self.server_boosts.lock().await;
        let expired: Vec<ServerBoost> = boosts
            .values()
            .filter(|b| b.is_expired(now_ms))
            .cloned()
            .collect();
        for boost in &expired {
            boosts.remove(&boost.id);
        }
        Ok(expired)
    }

    async fn fetch_boosted_server_ids(&self) -> Result<Vec<String>> {
        let boosts = self.server_boosts.lock().await;
        let mut ids: Vec<String> = boosts.values().filter_map(|b| b.server_id.clone()).collect();
        ids.sort();
        ids.dedup();
        Ok(ids)
    }
}
