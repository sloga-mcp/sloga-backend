use revolt_result::Result;

use crate::ReferenceDb;
use crate::Respect;

use super::{AbstractUserRespect, RESPECT_FETCH_CAP};

#[async_trait]
impl AbstractUserRespect for ReferenceDb {
    async fn insert_respect(&self, respect: &Respect) -> Result<()> {
        let mut rows = self.user_respect.lock().await;
        // Parity with the Mongo unique {target_id, author_id} index: reject
        // a duplicate pair (not just a duplicate id), with the same
        // `NoEffect` domain error the duplicate-key rejection maps to there.
        // Single Mutex = check and insert are atomic, so this is a real
        // guard and not the caller's TOCTOU probe repeated.
        if rows
            .values()
            .any(|row| row.target_id == respect.target_id && row.author_id == respect.author_id)
        {
            return Err(create_error!(NoEffect));
        }
        if rows.insert(respect.id.to_string(), respect.clone()).is_some() {
            Err(create_database_error!("insert", "user_respect"))
        } else {
            Ok(())
        }
    }

    async fn fetch_respect(&self, target_id: &str, author_id: &str) -> Result<Option<Respect>> {
        let rows = self.user_respect.lock().await;
        Ok(rows
            .values()
            .find(|row| row.target_id == target_id && row.author_id == author_id)
            .cloned())
    }

    async fn update_respect(&self, id: &str, content: &str, updated_at: i64) -> Result<()> {
        let mut rows = self.user_respect.lock().await;
        if let Some(row) = rows.get_mut(id) {
            row.content = content.to_string();
            row.updated_at = updated_at;
        }
        Ok(())
    }

    async fn fetch_respect_by_target(&self, target_id: &str) -> Result<Vec<Respect>> {
        let rows = self.user_respect.lock().await;
        // The newest-first sort is part of the trait contract — a HashMap
        // iterates in arbitrary order.
        let mut wall: Vec<Respect> = rows
            .values()
            .filter(|row| row.target_id == target_id)
            .cloned()
            .collect();
        wall.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        wall.truncate(RESPECT_FETCH_CAP as usize);
        Ok(wall)
    }

    async fn delete_respect(&self, id: &str) -> Result<()> {
        // Idempotent: a missing id is a no-op.
        let mut rows = self.user_respect.lock().await;
        rows.remove(id);
        Ok(())
    }

    async fn delete_respect_between(&self, user_a: &str, user_b: &str) -> Result<()> {
        let mut rows = self.user_respect.lock().await;
        rows.retain(|_, row| {
            !((row.target_id == user_a && row.author_id == user_b)
                || (row.target_id == user_b && row.author_id == user_a))
        });
        Ok(())
    }

    async fn delete_respect_involving(&self, user_id: &str) -> Result<()> {
        let mut rows = self.user_respect.lock().await;
        rows.retain(|_, row| row.target_id != user_id && row.author_id != user_id);
        Ok(())
    }
}
