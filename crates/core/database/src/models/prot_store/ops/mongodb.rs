use bson::Document;
use futures::TryStreamExt;
use mongodb::options::ReturnDocument;
use revolt_models::v0;
use revolt_result::Result;

use crate::{MongoDb, ProtStoreCursor, ProtStoreIntent, ProtStorePurchase};

use super::super::model::{unconsumed_play_filter, unconsumed_play_prot, NEEDS_UNCONSUMED};
use super::AbstractProtStore;

static INTENTS: &str = "prot_store_intents";
static PURCHASES: &str = "prot_store_purchases";
static CURSORS: &str = "prot_store_cursors";

// Every write to a purchase row `$inc`s its version (audit N2), so a store
// move planned on an older copy misses its CAS (apply_store_purchase_move).
// The indexes come from the migration only (revision 81).

/// 11000, as a write error or a command error
fn is_duplicate_key(error: &mongodb::error::Error) -> bool {
    match &*error.kind {
        mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(write_error)) => {
            write_error.code == 11000
        }
        mongodb::error::ErrorKind::Command(command_error) => command_error.code == 11000,
        _ => false,
    }
}

/// Rows a list method returns: `limit`, at least 1
fn take(limit: i64) -> i64 {
    limit.max(1)
}

/// bson stores a u64 as Int64: a version past i64::MAX cannot be matched
fn stored_version(version: u64) -> Result<i64> {
    i64::try_from(version).map_err(|_| {
        log::error!("PROT_STORE_VERSION_OVERFLOW version={version}");
        create_error!(InternalError)
    })
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

/// The states whose rows a sum reads, as stored
fn states(states: &[v0::ProtStoreState]) -> Vec<&'static str> {
    states.iter().map(|state| state.as_str()).collect()
}

impl MongoDb {
    async fn prot_store_rows(
        &self,
        filter: Document,
        sort: Option<Document>,
        limit: Option<i64>,
    ) -> Result<Vec<ProtStorePurchase>> {
        let col = self.col::<ProtStorePurchase>(PURCHASES);
        let mut find = col.find(filter);
        if let Some(sort) = sort {
            find = find.sort(sort);
        }
        if let Some(limit) = limit {
            find = find.limit(limit);
        }
        find.await
            .map_err(|_| create_database_error!("find", PURCHASES))?
            .try_collect()
            .await
            .map_err(|_| create_database_error!("find", PURCHASES))
    }

    async fn prot_store_intents(
        &self,
        filter: Document,
        limit: Option<i64>,
    ) -> Result<Vec<ProtStoreIntent>> {
        let col = self.col::<ProtStoreIntent>(INTENTS);
        let mut find = col.find(filter).sort(doc! { "_id": 1_i32 });
        if let Some(limit) = limit {
            find = find.limit(limit);
        }
        find.await
            .map_err(|_| create_database_error!("find", INTENTS))?
            .try_collect()
            .await
            .map_err(|_| create_database_error!("find", INTENTS))
    }

    /// Σ prot of the rows matching `filter`
    async fn prot_store_sum(&self, filter: Document) -> Result<i64> {
        Ok(self
            .prot_store_rows(filter, None, None)
            .await?
            .iter()
            .fold(0_i64, |total, row| total.saturating_add(row.prot)))
    }

    /// One bookkeeping write: `update` (which `$inc`s the version) where
    /// `filter` matches; Ok(true) when a row changed
    async fn prot_store_bookkeeping(&self, filter: Document, update: Document) -> Result<bool> {
        self.col::<Document>(PURCHASES)
            .update_one(filter, update)
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", PURCHASES))
    }
}

#[async_trait]
impl AbstractProtStore for MongoDb {
    async fn insert_prot_store_intent(&self, intent: &ProtStoreIntent) -> Result<()> {
        // A duplicate token (the unique index) is refused like any failure;
        // the engine re-generates the token once
        self.col::<ProtStoreIntent>(INTENTS)
            .insert_one(intent)
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("insert_one", INTENTS))
    }

    async fn fetch_prot_store_intent(&self, id: &str) -> Result<Option<ProtStoreIntent>> {
        self.col::<ProtStoreIntent>(INTENTS)
            .find_one(doc! { "_id": id })
            .await
            .map_err(|_| create_database_error!("find_one", INTENTS))
    }

    async fn fetch_prot_store_intent_by_token(
        &self,
        token: &str,
    ) -> Result<Option<ProtStoreIntent>> {
        self.col::<ProtStoreIntent>(INTENTS)
            .find_one(doc! { "token": token })
            .await
            .map_err(|_| create_database_error!("find_one", INTENTS))
    }

    async fn fetch_open_prot_store_intents(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<ProtStoreIntent>> {
        self.prot_store_intents(
            doc! {
                "user_id": user_id,
                "state": "Open",
                "expires_at": { "$gt": now }
            },
            None,
        )
        .await
    }

    async fn fetch_live_prot_store_intents(
        &self,
        user_id: &str,
        now: i64,
    ) -> Result<Vec<ProtStoreIntent>> {
        // Bounded by `prot_store_intents_user_state` (user_id prefix)
        self.prot_store_intents(
            doc! {
                "user_id": user_id,
                "state": { "$ne": "Used" },
                "expires_at": { "$gt": now }
            },
            None,
        )
        .await
    }

    async fn expire_prot_store_intents(&self, now: i64, limit: i64) -> Result<u64> {
        let due = doc! {
            "state": "Open",
            "expires_at": { "$lte": now }
        };
        let ids: Vec<String> = self
            .prot_store_intents(due.clone(), Some(take(limit)))
            .await?
            .into_iter()
            .map(|intent| intent.id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }

        let mut filter = due;
        filter.insert("_id", doc! { "$in": ids });
        self.col::<Document>(INTENTS)
            .update_many(filter, doc! { "$set": { "state": "Expired" } })
            .await
            .map(|result| result.modified_count)
            .map_err(|_| create_database_error!("update_many", INTENTS))
    }

    async fn fetch_prot_store_purchase(&self, id: &str) -> Result<Option<ProtStorePurchase>> {
        self.col::<ProtStorePurchase>(PURCHASES)
            .find_one(doc! { "_id": id })
            .await
            .map_err(|_| create_database_error!("find_one", PURCHASES))
    }

    async fn fetch_prot_store_needs_action(&self, limit: i64) -> Result<Vec<ProtStorePurchase>> {
        self.prot_store_rows(
            doc! { "needs_action": { "$type": "string" } },
            Some(doc! { "updated_at": -1_i32, "_id": 1_i32 }),
            Some(limit.clamp(1, 100)),
        )
        .await
    }

    async fn fetch_prot_store_purchases_by_state(
        &self,
        store: v0::ProtStore,
        state: v0::ProtStoreState,
        limit: i64,
    ) -> Result<Vec<ProtStorePurchase>> {
        self.prot_store_rows(
            doc! { "state": state.as_str(), "store": store.as_str() },
            Some(doc! { "created_at": 1_i32, "_id": 1_i32 }),
            Some(take(limit)),
        )
        .await
    }

    async fn fetch_unconsumed_play_purchases(&self, limit: i64) -> Result<Vec<ProtStorePurchase>> {
        self.prot_store_rows(
            doc! { "unconsumed": true, "store": v0::ProtStore::Play.as_str() },
            Some(doc! { "credited_at": 1_i32, "_id": 1_i32 }),
            Some(take(limit)),
        )
        .await
    }

    async fn mark_prot_store_consumed(
        &self,
        id: &str,
        expected_version: u64,
        at: i64,
    ) -> Result<bool> {
        // Read, then CAS on the version: every write bumps it, so the row
        // cannot have changed in between unless the CAS misses
        let Some(row) = self.fetch_prot_store_purchase(id).await? else {
            return Ok(false);
        };
        if row.version != expected_version || row.store != v0::ProtStore::Play || row.play.is_none()
        {
            return Ok(false);
        }

        let version = stored_version(expected_version)?;
        let mut unset = doc! { "unconsumed": "" };
        if row.needs_action.as_deref() == Some(NEEDS_UNCONSUMED) {
            unset.insert("needs_action", "");
        }
        self.prot_store_bookkeeping(
            doc! { "_id": id, "version": version },
            doc! {
                "$unset": unset,
                "$set": { "play.consumed_at": at, "updated_at": at },
                "$inc": { "version": 1_i64 }
            },
        )
        .await
    }

    async fn set_prot_store_needs_action(&self, id: &str, kind: &str, now: i64) -> Result<bool> {
        self.prot_store_bookkeeping(
            doc! { "_id": id, "needs_action": { "$ne": kind } },
            doc! {
                "$set": { "needs_action": kind, "updated_at": now },
                "$inc": { "version": 1_i64 }
            },
        )
        .await
    }

    async fn clear_prot_store_needs_action(&self, id: &str, kind: &str, now: i64) -> Result<bool> {
        self.prot_store_bookkeeping(
            doc! { "_id": id, "needs_action": kind },
            doc! {
                "$unset": { "needs_action": "" },
                "$set": { "updated_at": now },
                "$inc": { "version": 1_i64 }
            },
        )
        .await
    }

    async fn claim_prot_store_alert(&self, id: &str, kind: &str) -> Result<bool> {
        // Only the caller whose write added the kind sees a change
        self.prot_store_bookkeeping(
            doc! { "_id": id, "alerted": { "$ne": kind } },
            doc! {
                "$addToSet": { "alerted": kind },
                "$set": { "updated_at": now_ms() },
                "$inc": { "version": 1_i64 }
            },
        )
        .await
    }

    async fn sum_unconsumed_play_prot(&self, user_id: &str, before_ms: i64) -> Result<i64> {
        let rows = self
            .prot_store_rows(unconsumed_play_filter(user_id, before_ms), None, None)
            .await?;
        Ok(unconsumed_play_prot(&rows, user_id, before_ms))
    }

    async fn cancel_prot_store_intent(
        &self,
        id: &str,
        user_id: &str,
    ) -> Result<Option<ProtStoreIntent>> {
        let cancelled = self
            .col::<ProtStoreIntent>(INTENTS)
            .find_one_and_update(
                doc! { "_id": id, "user_id": user_id, "state": "Open" },
                doc! { "$set": { "state": "Expired" } },
            )
            .return_document(ReturnDocument::After)
            .await
            .map_err(|_| create_database_error!("find_one_and_update", INTENTS))?;
        if cancelled.is_some() {
            return Ok(cancelled);
        }

        // Theirs but no longer Open (an Expired intent still binds a late
        // purchase; a Used one is kept): reported as it is
        self.col::<ProtStoreIntent>(INTENTS)
            .find_one(doc! { "_id": id, "user_id": user_id })
            .await
            .map_err(|_| create_database_error!("find_one", INTENTS))
    }

    async fn delete_stale_prot_store_intents(&self, before_ms: i64, limit: i64) -> Result<u64> {
        let stale = doc! {
            "state": "Expired",
            "purchase_id": { "$exists": false },
            "expires_at": { "$lt": before_ms }
        };
        let ids: Vec<String> = self
            .prot_store_intents(stale.clone(), Some(take(limit)))
            .await?
            .into_iter()
            .map(|intent| intent.id)
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }

        let mut filter = stale;
        filter.insert("_id", doc! { "$in": ids });
        self.col::<Document>(INTENTS)
            .delete_many(filter)
            .await
            .map(|result| result.deleted_count)
            .map_err(|_| create_database_error!("delete_many", INTENTS))
    }

    async fn sum_sandbox_prot_store(&self, user_id: &str) -> Result<i64> {
        self.prot_store_sum(doc! {
            "user_id": user_id,
            "environment": "Sandbox",
            "state": {
                "$in": states(&[
                    v0::ProtStoreState::Credited,
                    v0::ProtStoreState::Reinstated,
                    v0::ProtStoreState::Held
                ])
            }
        })
        .await
    }

    async fn sum_held_prot_store(&self, user_id: &str) -> Result<i64> {
        self.prot_store_sum(doc! {
            "user_id": user_id,
            "state": v0::ProtStoreState::Held.as_str()
        })
        .await
    }

    async fn unlink_prot_store_user(&self, user_id: &str) -> Result<()> {
        // Each step is idempotent, so a failed unlink is re-run whole
        self.col::<Document>(INTENTS)
            .update_many(
                doc! { "user_id": user_id, "state": "Open" },
                doc! { "$set": { "state": "Expired" } },
            )
            .await
            .map_err(|_| create_database_error!("update_many", INTENTS))?;
        self.col::<Document>(INTENTS)
            .update_many(
                doc! { "user_id": user_id },
                doc! { "$unset": { "user_id": "" } },
            )
            .await
            .map_err(|_| create_database_error!("update_many", INTENTS))?;
        self.col::<Document>(PURCHASES)
            .update_many(
                doc! { "user_id": user_id },
                doc! {
                    "$unset": { "user_id": "" },
                    "$set": { "updated_at": now_ms() },
                    "$inc": { "version": 1_i64 }
                },
            )
            .await
            .map_err(|_| create_database_error!("update_many", PURCHASES))?;
        Ok(())
    }

    async fn fetch_prot_store_cursor(&self, id: &str) -> Result<Option<ProtStoreCursor>> {
        self.col::<ProtStoreCursor>(CURSORS)
            .find_one(doc! { "_id": id })
            .await
            .map_err(|_| create_database_error!("find_one", CURSORS))
    }

    async fn put_prot_store_cursor(
        &self,
        cursor: &ProtStoreCursor,
        expected_version: Option<u64>,
    ) -> Result<bool> {
        let col = self.col::<ProtStoreCursor>(CURSORS);
        match expected_version {
            None => match col
                .insert_one(ProtStoreCursor {
                    version: 0,
                    ..cursor.clone()
                })
                .await
            {
                Ok(_) => Ok(true),
                // Another replica inserted it first
                Err(error) if is_duplicate_key(&error) => Ok(false),
                Err(_) => Err(create_database_error!("insert_one", CURSORS)),
            },
            Some(expected) => {
                let version = stored_version(expected)?;
                let next = ProtStoreCursor {
                    version: expected.saturating_add(1),
                    ..cursor.clone()
                };
                col.replace_one(doc! { "_id": &cursor.id, "version": version }, next)
                    .await
                    .map(|result| result.matched_count == 1)
                    .map_err(|_| create_database_error!("replace_one", CURSORS))
            }
        }
    }
}
