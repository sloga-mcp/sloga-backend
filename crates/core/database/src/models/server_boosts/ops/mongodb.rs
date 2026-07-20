use bson::Document;
use futures::StreamExt;
use revolt_result::Result;

use crate::MongoDb;
use crate::ServerBoost;

use super::AbstractServerBoosts;

static COL: &str = "server_boosts";

/// Filter fragment: slot not expired at `now_ms`.
///
/// `expires_at` is a sparse field (absent = permanent), so "unexpired" is
/// "absent OR > now" — a bare `$gt` would silently drop permanent slots.
fn unexpired(now_ms: i64) -> Document {
    doc! {
        "$or": [
            { "expires_at": { "$exists": false } },
            { "expires_at": { "$gt": now_ms } }
        ]
    }
}

#[async_trait]
impl AbstractServerBoosts for MongoDb {
    async fn insert_server_boost(&self, boost: &ServerBoost) -> Result<()> {
        query!(self, insert_one, COL, &boost).map(|_| ())
    }

    async fn fetch_server_boost(&self, id: &str) -> Result<ServerBoost> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_server_boosts_by_user(&self, user_id: &str) -> Result<Vec<ServerBoost>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "user_id": user_id
            }
        )
    }

    async fn fetch_server_boosts_by_server(&self, server_id: &str) -> Result<Vec<ServerBoost>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "server_id": server_id
            }
        )
    }

    async fn count_server_boosts_by_server(&self, server_id: &str, now_ms: i64) -> Result<u64> {
        self.col::<Document>(COL)
            .count_documents(doc! {
                "server_id": server_id,
                "$or": [
                    { "expires_at": { "$exists": false } },
                    { "expires_at": { "$gt": now_ms } }
                ]
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    async fn count_unallocated_server_boosts(&self, user_id: &str, now_ms: i64) -> Result<u64> {
        // `server_id: None` is stored as an ABSENT field ($exists, not null-eq).
        self.col::<Document>(COL)
            .count_documents(doc! {
                "user_id": user_id,
                "server_id": { "$exists": false },
                "$or": [
                    { "expires_at": { "$exists": false } },
                    { "expires_at": { "$gt": now_ms } }
                ]
            })
            .await
            .map_err(|_| create_database_error!("count_documents", COL))
    }

    async fn allocate_server_boosts(
        &self,
        user_id: &str,
        server_id: &str,
        count: u32,
        now_ms: i64,
    ) -> Result<Vec<String>> {
        // One find_one_and_update per slot: each call atomically claims a
        // single unallocated, unexpired slot, so two concurrent allocations
        // can never double-spend one document. Fewer than `count` claims
        // means a racer won — the route rolls back via
        // deallocate_server_boosts_by_ids.
        let mut claimed = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut filter = doc! {
                "user_id": user_id,
                "server_id": { "$exists": false },
            };
            filter.extend(unexpired(now_ms));

            let slot = self
                .col::<ServerBoost>(COL)
                .find_one_and_update(
                    filter,
                    doc! {
                        "$set": {
                            "server_id": server_id,
                            "allocated_at": now_ms
                        }
                    },
                )
                .await
                .map_err(|_| create_database_error!("find_one_and_update", COL))?;

            match slot {
                Some(slot) => claimed.push(slot.id),
                None => break,
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
        // update_many cannot cap the number of documents it touches, so
        // resolve the target ids first (bounded find), then unset those.
        let col = self.col::<ServerBoost>(COL);
        let mut find = col.find(doc! {
            "user_id": user_id,
            "server_id": server_id
        });
        if let Some(count) = count {
            find = find.limit(count as i64);
        }

        let ids: Vec<String> = find
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .map(|slot| slot.id)
            .collect()
            .await;

        if ids.is_empty() {
            return Ok(0);
        }

        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "_id": { "$in": &ids },
                    // Belt-and-suspenders: never free someone else's slots
                    // even if the id list were somehow wrong.
                    "user_id": user_id
                },
                doc! {
                    "$unset": {
                        "server_id": 1_i32,
                        "allocated_at": 1_i32
                    }
                },
            )
            .await
            .map(|result| result.modified_count)
            .map_err(|_| create_database_error!("update_many", COL))
    }

    async fn deallocate_server_boosts_by_ids(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }

        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "_id": { "$in": ids }
                },
                doc! {
                    "$unset": {
                        "server_id": 1_i32,
                        "allocated_at": 1_i32
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_many", COL))
    }

    async fn deallocate_all_server_boosts_for_server(&self, server_id: &str) -> Result<u64> {
        self.col::<Document>(COL)
            .update_many(
                doc! {
                    "server_id": server_id
                },
                doc! {
                    "$unset": {
                        "server_id": 1_i32,
                        "allocated_at": 1_i32
                    }
                },
            )
            .await
            .map(|result| result.modified_count)
            .map_err(|_| create_database_error!("update_many", COL))
    }

    async fn delete_server_boosts_by_user(&self, user_id: &str) -> Result<Vec<String>> {
        let slots = self.fetch_server_boosts_by_user(user_id).await?;

        let mut affected: Vec<String> = slots.into_iter().filter_map(|slot| slot.server_id).collect();
        affected.sort();
        affected.dedup();

        self.col::<Document>(COL)
            .delete_many(doc! {
                "user_id": user_id
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(affected)
    }

    async fn delete_server_boost(&self, id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, id).map(|_| ())
    }

    async fn delete_expired_server_boosts(&self, now_ms: i64) -> Result<Vec<ServerBoost>> {
        // `$lte` never matches an absent field, so permanent slots
        // (no expires_at) are naturally excluded.
        let expired: Vec<ServerBoost> = self
            .col::<ServerBoost>(COL)
            .find(doc! {
                "expires_at": { "$lte": now_ms }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        if expired.is_empty() {
            return Ok(expired);
        }

        let ids: Vec<&str> = expired.iter().map(|slot| slot.id.as_str()).collect();
        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id": { "$in": ids }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL))?;

        Ok(expired)
    }

    async fn fetch_boosted_server_ids(&self) -> Result<Vec<String>> {
        self.col::<Document>(COL)
            .distinct(
                "server_id",
                doc! {
                    "server_id": { "$exists": true }
                },
            )
            .await
            .map(|values| {
                values
                    .into_iter()
                    .filter_map(|value| value.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .map_err(|_| create_database_error!("distinct", COL))
    }
}
