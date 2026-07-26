use revolt_result::Result;

use crate::ReferenceDb;
use crate::{SoftResReserveRow, SoftResSheet};

use super::AbstractSoftRes;

#[async_trait]
impl AbstractSoftRes for ReferenceDb {
    /// Insert a new sheet, enforcing one sheet per event.
    async fn insert_sheet(&self, sheet: &SoftResSheet) -> Result<()> {
        // This driver has no index machinery, so the unique constraints
        // (`message`, sparse `event`) are enforced in code under the
        // mutex — the dual-driver contract for the double-link race.
        let mut sheets = self.softres_sheets.lock().await;
        if sheets.contains_key(&sheet.id)
            || sheets.values().any(|existing| existing.message == sheet.message)
        {
            return Err(create_database_error!("insert", "softres_sheets"));
        }
        if let Some(event) = &sheet.event {
            if sheets
                .values()
                .any(|existing| existing.event.as_ref() == Some(event))
            {
                return Err(create_error!(SoftResEventAlreadyLinked));
            }
        }
        sheets.insert(sheet.id.to_string(), sheet.clone());
        Ok(())
    }

    /// Fetch a sheet by its id.
    async fn fetch_sheet(&self, id: &str) -> Result<SoftResSheet> {
        let sheets = self.softres_sheets.lock().await;
        sheets
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch several sheets by id.
    async fn fetch_sheets(&self, ids: &[String]) -> Result<Vec<SoftResSheet>> {
        let sheets = self.softres_sheets.lock().await;
        Ok(ids.iter().filter_map(|id| sheets.get(id).cloned()).collect())
    }

    /// Fetch the sheet linked to a calendar event, if any.
    async fn fetch_sheet_by_event(&self, event: &str) -> Result<Option<SoftResSheet>> {
        let sheets = self.softres_sheets.lock().await;
        Ok(sheets
            .values()
            .find(|sheet| sheet.event.as_deref() == Some(event))
            .cloned())
    }

    /// Overwrite the editable settings of a sheet (never `locked`).
    async fn update_sheet_settings(&self, sheet: &SoftResSheet) -> Result<()> {
        let mut sheets = self.softres_sheets.lock().await;
        if let Some(stored) = sheets.get_mut(&sheet.id) {
            stored.title = sheet.title.clone();
            stored.reserves_per_user = sheet.reserves_per_user;
            stored.per_item_cap = sheet.per_item_cap;
            stored.allow_duplicates = sheet.allow_duplicates;
            stored.class_restriction = sheet.class_restriction;
            stored.hidden = sheet.hidden;
            stored.lock_at_event_start = sheet.lock_at_event_start;
            stored.locks_at = sheet.locks_at;
            stored.note = sheet.note.clone();
            stored.hard_reserves = sheet.hard_reserves.clone();
            stored.edited_at = sheet.edited_at;
        }
        Ok(())
    }

    /// Atomically flip `locked` false→true. The mutex makes check-and-set
    /// atomic on this driver.
    async fn set_sheet_locked_if_unlocked(&self, id: &str) -> Result<bool> {
        let mut sheets = self.softres_sheets.lock().await;
        match sheets.get_mut(id) {
            Some(sheet) if !sheet.locked => {
                sheet.locked = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Unlock a sheet: clears `locked`, `locks_at` and
    /// `lock_at_event_start` (see the trait docs for why all three).
    async fn set_sheet_unlocked(&self, id: &str) -> Result<()> {
        let mut sheets = self.softres_sheets.lock().await;
        if let Some(sheet) = sheets.get_mut(id) {
            sheet.locked = false;
            sheet.locks_at = None;
            sheet.lock_at_event_start = false;
        }
        Ok(())
    }

    /// Insert or replace a user's reserve row, returning the previous row
    /// if one existed.
    async fn upsert_reserve(
        &self,
        row: &SoftResReserveRow,
    ) -> Result<Option<SoftResReserveRow>> {
        let mut reserves = self.softres_reserves.lock().await;
        Ok(reserves.insert(row.id.to_string(), row.clone()))
    }

    /// Remove a user's reserve row, returning it if it existed.
    async fn remove_reserve(
        &self,
        sheet: &str,
        user: &str,
    ) -> Result<Option<SoftResReserveRow>> {
        let mut reserves = self.softres_reserves.lock().await;
        Ok(reserves.remove(&SoftResSheet::reserve_key(sheet, user)))
    }

    /// Fetch a single user's reserve row on a sheet, if any.
    async fn fetch_reserve(
        &self,
        sheet: &str,
        user: &str,
    ) -> Result<Option<SoftResReserveRow>> {
        let reserves = self.softres_reserves.lock().await;
        Ok(reserves.get(&SoftResSheet::reserve_key(sheet, user)).cloned())
    }

    /// Fetch every reserve row on a sheet.
    async fn fetch_reserves_for_sheet(&self, sheet: &str) -> Result<Vec<SoftResReserveRow>> {
        let reserves = self.softres_reserves.lock().await;
        Ok(reserves
            .values()
            .filter(|row| row.sheet == sheet)
            .cloned()
            .collect())
    }

    /// Count reserve copies of an item, excluding one user's rows.
    /// Copies, not rows — with duplicates allowed one row can hold the
    /// item several times.
    async fn count_item_reservations(
        &self,
        sheet: &str,
        item_id: u32,
        exclude_user: &str,
    ) -> Result<u32> {
        let reserves = self.softres_reserves.lock().await;
        Ok(reserves
            .values()
            .filter(|row| row.sheet == sheet && row.user != exclude_user)
            .flat_map(|row| row.items.iter())
            .filter(|item| **item == item_id)
            .count() as u32)
    }

    /// Delete the sheets carried by the given messages, and their
    /// reserves.
    async fn delete_softres_for_messages(&self, message_ids: &[String]) -> Result<()> {
        let mut sheets = self.softres_sheets.lock().await;
        let sheet_ids: Vec<String> = sheets
            .values()
            .filter(|sheet| message_ids.contains(&sheet.message))
            .map(|sheet| sheet.id.clone())
            .collect();

        if sheet_ids.is_empty() {
            return Ok(());
        }

        sheets.retain(|id, _| !sheet_ids.contains(id));

        let mut reserves = self.softres_reserves.lock().await;
        reserves.retain(|_, row| !sheet_ids.contains(&row.sheet));
        Ok(())
    }

    /// Delete every sheet and reserve in a channel.
    async fn delete_softres_for_channel(&self, channel: &str) -> Result<()> {
        let mut sheets = self.softres_sheets.lock().await;
        sheets.retain(|_, sheet| sheet.channel != channel);

        let mut reserves = self.softres_reserves.lock().await;
        reserves.retain(|_, row| row.channel != channel);
        Ok(())
    }

    /// Delete every sheet and reserve in a server. Reserve rows carry no
    /// server id, so they are resolved through the sheets.
    async fn delete_softres_for_server(&self, server: &str) -> Result<()> {
        let mut sheets = self.softres_sheets.lock().await;
        let sheet_ids: Vec<String> = sheets
            .values()
            .filter(|sheet| sheet.server.as_deref() == Some(server))
            .map(|sheet| sheet.id.clone())
            .collect();

        sheets.retain(|id, _| !sheet_ids.contains(id));

        let mut reserves = self.softres_reserves.lock().await;
        reserves.retain(|_, row| !sheet_ids.contains(&row.sheet));
        Ok(())
    }
}
