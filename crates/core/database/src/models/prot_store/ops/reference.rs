use revolt_models::v0;
use revolt_result::Result;

use crate::{ProtStoreCursor, ProtStoreIntent, ProtStorePurchase, ReferenceDb};

use super::super::model::{unconsumed_play_prot, NEEDS_UNCONSUMED};
use super::AbstractProtStore;

// Lock order (models/prot/mod.rs): prot_store_intents -> prot_store_purchases
// -> prot_store_cursors. Each method takes only its own store map, except
// the unlink, which takes the intents and then the purchases; none takes a
// ledger map (a store move takes those first, in apply_store_purchase_move).
// Every write to a purchase row bumps its version (audit N2).

/// Rows a list method returns: `limit`, at least 1
fn take(limit: i64) -> usize {
    usize::try_from(limit.max(1)).unwrap_or(usize::MAX)
}

/// Wall-clock now, epoch ms: the unlink and the alert claim take no `now`
/// but stamp `updated_at` like every other row write (W1 audit NIT 4)
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

/// Every write to a purchase row bumps its version (audit N2)
fn bump(row: &mut ProtStorePurchase) {
    row.version = row.version.saturating_add(1);
}

#[async_trait]
impl AbstractProtStore for ReferenceDb {
    async fn insert_prot_store_intent(&self, intent: &ProtStoreIntent) -> Result<()> {
        let mut intents = self.prot_store_intents.lock().await;
        // The unique index on `token` (and `_id`), as in MongoDB
        if intents.contains_key(&intent.id)
            || intents.values().any(|stored| stored.token == intent.token)
        {
            return Err(create_database_error!("insert_one", "prot_store_intents"));
        }
        intents.insert(intent.id.clone(), intent.clone());
        Ok(())
    }

    async fn fetch_prot_store_intent(&self, id: &str) -> Result<Option<ProtStoreIntent>> {
        let intents = self.prot_store_intents.lock().await;
        Ok(intents.get(id).cloned())
    }

    async fn fetch_prot_store_intent_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ProtStoreIntent>> {
        let intents = self.prot_store_intents.lock().await;
        Ok(intents
            .values()
            .find(|intent| intent.token == token)
            .cloned())
    }

    async fn fetch_open_prot_store_intents(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<ProtStoreIntent>> {
        let intents = self.prot_store_intents.lock().await;
        let mut open: Vec<ProtStoreIntent> = intents
            .values()
            .filter(|intent| {
                intent.user_id.as_deref() == Some(user_id)
                    && intent.state == v0::ProtStoreIntentState::Open
                    && intent.expires_at > now
            })
            .cloned()
            .collect();
        open.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(open)
    }

    async fn fetch_live_prot_store_intents(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<ProtStoreIntent>> {
        let intents = self.prot_store_intents.lock().await;
        let mut live: Vec<ProtStoreIntent> = intents
            .values()
            .filter(|intent| {
                intent.user_id.as_deref() == Some(user_id)
                    && intent.state != v0::ProtStoreIntentState::Used
                    && intent.expires_at > now
            })
            .cloned()
            .collect();
        live.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(live)
    }

    async fn expire_prot_store_intents(&self, now: i64, limit: i64) -> Result<u64> {
        let mut intents = self.prot_store_intents.lock().await;
        let mut due: Vec<String> = intents
            .values()
            .filter(|intent| {
                intent.state == v0::ProtStoreIntentState::Open && intent.expires_at <= now
            })
            .map(|intent| intent.id.clone())
            .collect();
        due.sort();
        due.truncate(take(limit));

        for id in &due {
            if let Some(intent) = intents.get_mut(id) {
                intent.state = v0::ProtStoreIntentState::Expired;
            }
        }
        Ok(due.len() as u64)
    }

    async fn fetch_prot_store_purchase(&self, id: &str) -> Result<Option<ProtStorePurchase>> {
        let purchases = self.prot_store_purchases.lock().await;
        Ok(purchases.get(id).cloned())
    }

    async fn fetch_prot_store_needs_action(&self, limit: i64) -> Result<Vec<ProtStorePurchase>> {
        let purchases = self.prot_store_purchases.lock().await;
        let mut rows: Vec<ProtStorePurchase> = purchases
            .values()
            .filter(|row| row.needs_action.is_some())
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows.truncate(limit.clamp(1, 100) as usize);
        Ok(rows)
    }

    async fn fetch_prot_store_purchases_by_state(
        &self,
        store: v0::ProtStore,
        state: v0::ProtStoreState,
        limit: i64,
    ) -> Result<Vec<ProtStorePurchase>> {
        let purchases = self.prot_store_purchases.lock().await;
        let mut rows: Vec<ProtStorePurchase> = purchases
            .values()
            .filter(|row| row.store == store && row.state == state)
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows.truncate(take(limit));
        Ok(rows)
    }

    async fn fetch_unconsumed_play_purchases(&self, limit: i64) -> Result<Vec<ProtStorePurchase>> {
        let purchases = self.prot_store_purchases.lock().await;
        let mut rows: Vec<ProtStorePurchase> = purchases
            .values()
            .filter(|row| row.store == v0::ProtStore::Play && row.unconsumed == Some(true))
            .cloned()
            .collect();
        rows.sort_by(|a, b| {
            a.credited_at
                .cmp(&b.credited_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        rows.truncate(take(limit));
        Ok(rows)
    }

    async fn mark_prot_store_consumed(
        &self,
        id: &str,
        expected_version: u64,
        at: i64,
    ) -> Result<bool> {
        let mut purchases = self.prot_store_purchases.lock().await;
        let Some(row) = purchases.get_mut(id) else {
            return Ok(false);
        };
        if row.version != expected_version || row.store != v0::ProtStore::Play {
            return Ok(false);
        }
        let Some(play) = row.play.as_mut() else {
            return Ok(false);
        };

        play.consumed_at = Some(at);
        row.unconsumed = None;
        if row.needs_action.as_deref() == Some(NEEDS_UNCONSUMED) {
            row.needs_action = None;
        }
        row.updated_at = at;
        bump(row);
        Ok(true)
    }

    async fn set_prot_store_needs_action(&self, id: &str, kind: &str, now: i64) -> Result<bool> {
        let mut purchases = self.prot_store_purchases.lock().await;
        let Some(row) = purchases.get_mut(id) else {
            return Ok(false);
        };
        if row.needs_action.as_deref() == Some(kind) {
            return Ok(false);
        }
        row.needs_action = Some(kind.to_string());
        row.updated_at = now;
        bump(row);
        Ok(true)
    }

    async fn clear_prot_store_needs_action(&self, id: &str, kind: &str, now: i64) -> Result<bool> {
        let mut purchases = self.prot_store_purchases.lock().await;
        let Some(row) = purchases.get_mut(id) else {
            return Ok(false);
        };
        if row.needs_action.as_deref() != Some(kind) {
            return Ok(false);
        }
        row.needs_action = None;
        row.updated_at = now;
        bump(row);
        Ok(true)
    }

    async fn claim_prot_store_alert(&self, id: &str, kind: &str) -> Result<bool> {
        let mut purchases = self.prot_store_purchases.lock().await;
        let Some(row) = purchases.get_mut(id) else {
            return Ok(false);
        };
        if row.alerted.iter().any(|sent| sent == kind) {
            return Ok(false);
        }
        row.alerted.push(kind.to_string());
        row.updated_at = now_ms();
        bump(row);
        Ok(true)
    }

    async fn sum_unconsumed_play_prot(&self, user_id: &str, before_ms: i64) -> Result<i64> {
        let purchases = self.prot_store_purchases.lock().await;
        Ok(unconsumed_play_prot(purchases.values(), user_id, before_ms))
    }

    async fn cancel_prot_store_intent(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<ProtStoreIntent>> {
        let mut intents = self.prot_store_intents.lock().await;
        let Some(intent) = intents.get_mut(id) else {
            return Ok(None);
        };
        if intent.user_id.as_deref() != Some(user_id) {
            return Ok(None);
        }
        // An Expired intent still binds a late purchase; a Used one is kept
        if intent.state == v0::ProtStoreIntentState::Open {
            intent.state = v0::ProtStoreIntentState::Expired;
        }
        Ok(Some(intent.clone()))
    }

    async fn delete_stale_prot_store_intents(&self, before_ms: i64, limit: i64) -> Result<u64> {
        let mut intents = self.prot_store_intents.lock().await;
        let mut stale: Vec<String> = intents
            .values()
            .filter(|intent| {
                intent.state == v0::ProtStoreIntentState::Expired
                    && intent.purchase_id.is_none()
                    && intent.expires_at < before_ms
            })
            .map(|intent| intent.id.clone())
            .collect();
        stale.sort();
        stale.truncate(take(limit));

        for id in &stale {
            intents.remove(id);
        }
        Ok(stale.len() as u64)
    }

    async fn sum_sandbox_prot_store(&self, user_id: &str) -> Result<i64> {
        let purchases = self.prot_store_purchases.lock().await;
        Ok(purchases
            .values()
            .filter(|row| {
                row.user_id.as_deref() == Some(user_id)
                    && row.environment == v0::ProtStoreEnvironment::Sandbox
                    && matches!(
                        row.state,
                        v0::ProtStoreState::Credited
                            | v0::ProtStoreState::Reinstated
                            | v0::ProtStoreState::Held
                    )
            })
            .fold(0_i64, |total, row| total.saturating_add(row.prot)))
    }

    async fn sum_held_prot_store(&self, user_id: &str) -> Result<i64> {
        let purchases = self.prot_store_purchases.lock().await;
        Ok(purchases
            .values()
            .filter(|row| {
                row.user_id.as_deref() == Some(user_id) && row.state == v0::ProtStoreState::Held
            })
            .fold(0_i64, |total, row| total.saturating_add(row.prot)))
    }

    async fn unlink_prot_store_user(&self, user_id: &str) -> Result<()> {
        let now = now_ms();
        let mut intents = self.prot_store_intents.lock().await;
        let mut purchases = self.prot_store_purchases.lock().await;

        for intent in intents.values_mut() {
            if intent.user_id.as_deref() == Some(user_id) {
                intent.user_id = None;
                if intent.state == v0::ProtStoreIntentState::Open {
                    intent.state = v0::ProtStoreIntentState::Expired;
                }
            }
        }
        for row in purchases.values_mut() {
            if row.user_id.as_deref() == Some(user_id) {
                row.user_id = None;
                bump(row);
                row.updated_at = now;
            }
        }
        Ok(())
    }

    async fn fetch_prot_store_cursor(&self, id: &str) -> Result<Option<ProtStoreCursor>> {
        let cursors = self.prot_store_cursors.lock().await;
        Ok(cursors.get(id).cloned())
    }

    async fn put_prot_store_cursor(
        &self,
        cursor: &ProtStoreCursor,
        expected_version: Option<u64>,
    ) -> Result<bool> {
        let mut cursors = self.prot_store_cursors.lock().await;
        let version = match (expected_version, cursors.get(&cursor.id)) {
            (None, None) => 0,
            (Some(expected), Some(stored)) if stored.version == expected => {
                expected.saturating_add(1)
            }
            _ => return Ok(false),
        };
        cursors.insert(
            cursor.id.clone(),
            ProtStoreCursor {
                version,
                ..cursor.clone()
            },
        );
        Ok(true)
    }
}
