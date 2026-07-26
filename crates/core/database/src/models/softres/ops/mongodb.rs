use bson::{to_bson, Document};
use futures::StreamExt;
use mongodb::options::{FindOneAndReplaceOptions, ReturnDocument};
use revolt_result::Result;

use crate::MongoDb;
use crate::{SoftResReserveRow, SoftResSheet};

use super::AbstractSoftRes;

static COL: &str = "softres_sheets";
static COL_RESERVES: &str = "softres_reserves";

#[async_trait]
impl AbstractSoftRes for MongoDb {
    /// Insert a new sheet, enforcing one sheet per event.
    async fn insert_sheet(&self, sheet: &SoftResSheet) -> Result<()> {
        // The `event` unique sparse index is what actually serializes the
        // concurrent double-link race — delta's validation is a TOCTOU
        // and two simultaneous creates both pass it. A duplicate-key
        // rejection on that index is the expected outcome of the race,
        // so it becomes the same 409 as the eager check; `_id` (fresh
        // ULID) and `message` (one create per message send) cannot
        // collide in practice, so anything else stays a database fault.
        self.col::<SoftResSheet>(COL)
            .insert_one(sheet)
            .await
            .map(|_| ())
            .map_err(|error| match *error.kind {
                mongodb::error::ErrorKind::Write(mongodb::error::WriteFailure::WriteError(
                    ref write_error,
                    // "index: event" pins the named index (E11000 has
                    // carried `index: <name>` across supported server
                    // versions) — a bare "event" substring could one day
                    // collide with another index's name/field/values.
                    // COUPLING: revisit if softres_sheets ever gains
                    // another unique index (today: _id_, message, event).
                )) if write_error.code == 11000
                    && write_error.message.contains("index: event") =>
                {
                    create_error!(SoftResEventAlreadyLinked)
                }
                _ => create_database_error!("insert_one", COL),
            })
    }

    /// Fetch a sheet by its id.
    async fn fetch_sheet(&self, id: &str) -> Result<SoftResSheet> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    /// Fetch several sheets by id.
    async fn fetch_sheets(&self, ids: &[String]) -> Result<Vec<SoftResSheet>> {
        Ok(self
            .col::<SoftResSheet>(COL)
            .find(doc! {
                "_id": {
                    "$in": ids
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Fetch the sheet linked to a calendar event, if any.
    async fn fetch_sheet_by_event(&self, event: &str) -> Result<Option<SoftResSheet>> {
        query!(self, find_one, COL, doc! { "event": event })
    }

    /// Overwrite the editable settings of a sheet (never `locked`).
    async fn update_sheet_settings(&self, sheet: &SoftResSheet) -> Result<()> {
        let mut set = doc! {
            "title": &sheet.title,
            "reserves_per_user": sheet.reserves_per_user as i32,
            "allow_duplicates": sheet.allow_duplicates,
            "class_restriction": sheet.class_restriction,
            "hidden": sheet.hidden,
            "lock_at_event_start": sheet.lock_at_event_start,
            "hard_reserves": to_bson(&sheet.hard_reserves)
                .map_err(|_| create_database_error!("to_bson", COL))?,
        };
        let mut unset = Document::new();

        match sheet.per_item_cap {
            Some(cap) => {
                set.insert("per_item_cap", cap as i32);
            }
            None => {
                unset.insert("per_item_cap", 1_i32);
            }
        }
        match &sheet.note {
            Some(note) => {
                set.insert("note", note);
            }
            None => {
                unset.insert("note", 1_i32);
            }
        }
        match sheet.locks_at {
            Some(locks_at) => {
                set.insert("locks_at", locks_at);
            }
            None => {
                unset.insert("locks_at", 1_i32);
            }
        }
        match sheet.edited_at {
            Some(edited_at) => {
                set.insert("edited_at", edited_at);
            }
            None => {
                unset.insert("edited_at", 1_i32);
            }
        }

        let mut update = doc! { "$set": set };
        if !unset.is_empty() {
            update.insert("$unset", unset);
        }

        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": &sheet.id
                },
                update,
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Atomically flip `locked` false→true.
    async fn set_sheet_locked_if_unlocked(&self, id: &str) -> Result<bool> {
        // `locked: false` is stored as a MISSING key (skip_serializing_if),
        // so match on "not true" rather than "false".
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id,
                    "locked": { "$ne": true }
                },
                doc! {
                    "$set": { "locked": true }
                },
            )
            .await
            .map(|result| result.modified_count == 1)
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Unlock a sheet: clears `locked`, `locks_at` and
    /// `lock_at_event_start` (see the trait docs for why all three).
    async fn set_sheet_unlocked(&self, id: &str) -> Result<()> {
        self.col::<Document>(COL)
            .update_one(
                doc! {
                    "_id": id
                },
                doc! {
                    "$unset": {
                        "locked": 1_i32,
                        "locks_at": 1_i32,
                        "lock_at_event_start": 1_i32
                    }
                },
            )
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("update_one", COL))
    }

    /// Insert or replace a user's reserve row, returning the previous row
    /// if one existed.
    async fn upsert_reserve(
        &self,
        row: &SoftResReserveRow,
    ) -> Result<Option<SoftResReserveRow>> {
        self.col::<SoftResReserveRow>(COL_RESERVES)
            .find_one_and_replace(
                doc! {
                    "_id": &row.id
                },
                row,
            )
            .with_options(
                FindOneAndReplaceOptions::builder()
                    .upsert(true)
                    .return_document(ReturnDocument::Before)
                    .build(),
            )
            .await
            .map_err(|_| create_database_error!("find_one_and_replace", COL_RESERVES))
    }

    /// Remove a user's reserve row, returning it if it existed.
    async fn remove_reserve(
        &self,
        sheet: &str,
        user: &str,
    ) -> Result<Option<SoftResReserveRow>> {
        self.col::<SoftResReserveRow>(COL_RESERVES)
            .find_one_and_delete(doc! {
                "_id": SoftResSheet::reserve_key(sheet, user)
            })
            .await
            .map_err(|_| create_database_error!("find_one_and_delete", COL_RESERVES))
    }

    /// Fetch a single user's reserve row on a sheet, if any.
    async fn fetch_reserve(
        &self,
        sheet: &str,
        user: &str,
    ) -> Result<Option<SoftResReserveRow>> {
        query!(
            self,
            find_one_by_id,
            COL_RESERVES,
            &SoftResSheet::reserve_key(sheet, user)
        )
    }

    /// Fetch every reserve row on a sheet.
    async fn fetch_reserves_for_sheet(&self, sheet: &str) -> Result<Vec<SoftResReserveRow>> {
        Ok(self
            .col::<SoftResReserveRow>(COL_RESERVES)
            .find(doc! {
                "sheet": sheet
            })
            .await
            .map_err(|_| create_database_error!("find", COL_RESERVES))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await)
    }

    /// Count reserve copies of an item, excluding one user's rows.
    async fn count_item_reservations(
        &self,
        sheet: &str,
        item_id: u32,
        exclude_user: &str,
    ) -> Result<u32> {
        // Copies, not rows: a row's `items` array can hold the item more
        // than once when duplicates are allowed, so the occurrences are
        // summed in code. Bounded by raid size (~25–40 rows), and the
        // multikey (sheet, items) index narrows the fetch to rows that
        // hold the item at all.
        let rows: Vec<SoftResReserveRow> = self
            .col::<SoftResReserveRow>(COL_RESERVES)
            .find(doc! {
                "sheet": sheet,
                "items": item_id as i64,
                "user": { "$ne": exclude_user }
            })
            .await
            .map_err(|_| create_database_error!("find", COL_RESERVES))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        Ok(rows
            .iter()
            .flat_map(|row| row.items.iter())
            .filter(|item| **item == item_id)
            .count() as u32)
    }

    /// Delete the sheets carried by the given messages, and their
    /// reserves.
    async fn delete_softres_for_messages(&self, message_ids: &[String]) -> Result<()> {
        let sheets: Vec<SoftResSheet> = self
            .col::<SoftResSheet>(COL)
            .find(doc! {
                "message": {
                    "$in": message_ids
                }
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        if sheets.is_empty() {
            return Ok(());
        }

        let sheet_ids: Vec<&str> = sheets.iter().map(|sheet| sheet.id.as_str()).collect();

        self.col::<Document>(COL_RESERVES)
            .delete_many(doc! {
                "sheet": {
                    "$in": &sheet_ids
                }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_RESERVES))?;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id": {
                    "$in": &sheet_ids
                }
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    /// Delete every sheet and reserve in a channel.
    async fn delete_softres_for_channel(&self, channel: &str) -> Result<()> {
        self.col::<Document>(COL_RESERVES)
            .delete_many(doc! {
                "channel": channel
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_RESERVES))?;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "channel": channel
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }

    /// Delete every sheet and reserve in a server. Reserve rows carry no
    /// server id, so they are resolved through the sheets.
    async fn delete_softres_for_server(&self, server: &str) -> Result<()> {
        let sheets: Vec<SoftResSheet> = self
            .col::<SoftResSheet>(COL)
            .find(doc! {
                "server": server
            })
            .await
            .map_err(|_| create_database_error!("find", COL))?
            .filter_map(|s| async { s.ok() })
            .collect()
            .await;

        if sheets.is_empty() {
            return Ok(());
        }

        let sheet_ids: Vec<&str> = sheets.iter().map(|sheet| sheet.id.as_str()).collect();

        self.col::<Document>(COL_RESERVES)
            .delete_many(doc! {
                "sheet": {
                    "$in": &sheet_ids
                }
            })
            .await
            .map_err(|_| create_database_error!("delete_many", COL_RESERVES))?;

        self.col::<Document>(COL)
            .delete_many(doc! {
                "_id": {
                    "$in": &sheet_ids
                }
            })
            .await
            .map(|_| ())
            .map_err(|_| create_database_error!("delete_many", COL))
    }
}
