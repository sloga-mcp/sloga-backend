use iso8601_timestamp::Timestamp;
use revolt_result::Result;

use crate::{ReferenceDb, TakedownRequest};

use super::AbstractTakedownRequests;

impl ReferenceDb {
    async fn filter_takedown_requests(
        &self,
        keep: impl Fn(&TakedownRequest) -> bool,
    ) -> Vec<TakedownRequest> {
        let rows = self.takedown_requests.lock().await;
        rows.values().filter(|row| keep(*row)).cloned().collect()
    }
}

#[async_trait]
impl AbstractTakedownRequests for ReferenceDb {
    async fn insert_takedown_request(&self, r: &TakedownRequest) -> Result<()> {
        let mut rows = self.takedown_requests.lock().await;
        if rows.contains_key(&r.id) {
            Err(create_database_error!("insert", "takedown_requests"))
        } else {
            rows.insert(r.id.clone(), r.clone());
            Ok(())
        }
    }

    async fn fetch_takedown_request(&self, id: &str) -> Result<TakedownRequest> {
        let rows = self.takedown_requests.lock().await;
        rows.get(id).cloned().ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_open_takedown_requests(&self) -> Result<Vec<TakedownRequest>> {
        let mut rows = self
            .filter_takedown_requests(|row| row.status.is_open())
            .await;
        // Same keys the Mongo impl sorts by; a HashMap has no order
        rows.sort_by(|a, b| (a.deadline_at, &a.id).cmp(&(b.deadline_at, &b.id)));
        Ok(rows)
    }

    async fn fetch_recent_takedown_requests(
        &self,
        since: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        let mut rows = self
            .filter_takedown_requests(|row| row.received_at >= since)
            .await;
        rows.sort_by(|a, b| (b.received_at, &b.id).cmp(&(a.received_at, &a.id)));
        Ok(rows)
    }

    async fn fetch_takedown_requests_by_contact_since(
        &self,
        contact_fp: &str,
        since: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        let mut rows = self
            .filter_takedown_requests(|row| {
                row.contact_fp == contact_fp && row.received_at >= since
            })
            .await;
        rows.sort_by(|a, b| (a.received_at, &a.id).cmp(&(b.received_at, &b.id)));
        Ok(rows)
    }

    async fn fetch_takedown_requests_hold_due(
        &self,
        now: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        let mut rows = self
            .filter_takedown_requests(|row| {
                row.hold_until.is_some_and(|hold_until| hold_until <= now)
                    && !row.held_files.is_empty()
                    && !row.child_safety
            })
            .await;
        rows.sort_by(|a, b| (a.hold_until, &a.id).cmp(&(b.hold_until, &b.id)));
        Ok(rows)
    }

    async fn fetch_takedown_requests_to_purge(
        &self,
        closed_before: Timestamp,
    ) -> Result<Vec<TakedownRequest>> {
        let mut rows = self
            .filter_takedown_requests(|row| {
                row.closed_at
                    .is_some_and(|closed_at| closed_at <= closed_before)
                    && !row.requester_purged
            })
            .await;
        rows.sort_by(|a, b| (a.closed_at, &a.id).cmp(&(b.closed_at, &b.id)));
        Ok(rows)
    }

    async fn replace_takedown_request(&self, r: &mut TakedownRequest) -> Result<()> {
        let mut rows = self.takedown_requests.lock().await;
        let stored = rows.get_mut(&r.id).ok_or_else(|| create_error!(NotFound))?;
        if stored.revision != r.revision {
            return Err(create_error!(InvalidOperation));
        }
        let next = r
            .revision
            .checked_add(1)
            .ok_or_else(|| create_database_error!("revision", "takedown_requests"))?;

        r.revision = next;
        let markers = std::mem::take(&mut stored.markers);
        *stored = r.clone();
        stored.markers = markers;
        Ok(())
    }

    async fn claim_takedown_marker(&self, id: &str, marker: &str) -> Result<bool> {
        let mut rows = self.takedown_requests.lock().await;
        let Some(row) = rows.get_mut(id) else {
            return Ok(false);
        };
        if row.markers.iter().any(|existing| existing == marker) {
            Ok(false)
        } else {
            row.markers.push(marker.to_string());
            Ok(true)
        }
    }
}
