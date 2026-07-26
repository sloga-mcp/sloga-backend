use revolt_result::Result;

use crate::{SoftResReserveRow, SoftResSheet};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

#[async_trait]
pub trait AbstractSoftRes: Sync + Send {
    /// Insert a new sheet. A duplicate non-None `event` link is rejected
    /// with `SoftResEventAlreadyLinked` (one sheet per event — enforced
    /// by a unique sparse index on Mongo, in code on the Reference
    /// driver, so the concurrent double-link race loses cleanly on both).
    async fn insert_sheet(&self, sheet: &SoftResSheet) -> Result<()>;

    /// Fetch a sheet by its id.
    async fn fetch_sheet(&self, id: &str) -> Result<SoftResSheet>;

    /// Fetch several sheets by id (bulk hydration for a page of messages).
    async fn fetch_sheets(&self, ids: &[String]) -> Result<Vec<SoftResSheet>>;

    /// Fetch the sheet linked to a calendar event, if any.
    async fn fetch_sheet_by_event(&self, event: &str) -> Result<Option<SoftResSheet>>;

    /// Overwrite the editable settings of a sheet from the given record:
    /// title, reserves_per_user, per_item_cap, allow_duplicates,
    /// class_restriction, hidden, lock_at_event_start, locks_at, note,
    /// hard_reserves, edited_at. The `locked` flag is NOT written — lock
    /// state changes only through the atomic lock/unlock ops, so an edit
    /// can never clobber a concurrent lock flip.
    async fn update_sheet_settings(&self, sheet: &SoftResSheet) -> Result<()>;

    /// Atomically flip `locked` false→true; returns whether THIS caller
    /// won the flip (exactly-once lock arbitration — the manual lock
    /// route and the event-cancel hook may race).
    async fn set_sheet_locked_if_unlocked(&self, id: &str) -> Result<bool>;

    /// Unlock a sheet: clears `locked`, `locks_at` AND
    /// `lock_at_event_start`. After the auto-lock instant has passed,
    /// clearing only the flag would leave the sheet permanently locked by
    /// the timestamp compare — and leaving `lock_at_event_start` set
    /// would advertise an auto-lock that can never fire (re-arming is an
    /// explicit edit, which re-snapshots `locks_at` from the event).
    async fn set_sheet_unlocked(&self, id: &str) -> Result<()>;

    /// Insert or replace a user's reserve row, returning the previous row
    /// if one existed (drives the WS delta and cap compensation).
    async fn upsert_reserve(&self, row: &SoftResReserveRow)
        -> Result<Option<SoftResReserveRow>>;

    /// Remove a user's reserve row, returning it if it existed.
    async fn remove_reserve(&self, sheet: &str, user: &str)
        -> Result<Option<SoftResReserveRow>>;

    /// Fetch a single user's reserve row on a sheet, if any.
    async fn fetch_reserve(&self, sheet: &str, user: &str)
        -> Result<Option<SoftResReserveRow>>;

    /// Fetch every reserve row on a sheet (bounded by raid size).
    async fn fetch_reserves_for_sheet(&self, sheet: &str) -> Result<Vec<SoftResReserveRow>>;

    /// Count reserve COPIES of an item across every row on the sheet
    /// except the excluded user's (their copies are counted separately by
    /// the caller from the incoming row). Copies, not rows: with
    /// duplicates allowed one raider may hold an item several times and
    /// each copy consumes per-item-cap headroom.
    async fn count_item_reservations(
        &self,
        sheet: &str,
        item_id: u32,
        exclude_user: &str,
    ) -> Result<u32>;

    /// Delete the sheets carried by the given messages, and their
    /// reserves (message-deletion cascade, single and bulk paths).
    async fn delete_softres_for_messages(&self, message_ids: &[String]) -> Result<()>;

    /// Delete every sheet and reserve in a channel (channel-deletion
    /// cascade).
    async fn delete_softres_for_channel(&self, channel: &str) -> Result<()>;

    /// Delete every sheet and reserve in a server (server-deletion
    /// cascade).
    async fn delete_softres_for_server(&self, server: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::AbstractSoftRes;
    use crate::{SoftResReserveRow, SoftResSheet};
    use revolt_models::v0;
    use revolt_result::ErrorType;

    fn sheet(id: &str, message: &str) -> SoftResSheet {
        SoftResSheet {
            id: id.to_string(),
            message: message.to_string(),
            channel: "01CHAN000000000000000000000".to_string(),
            server: Some("01SRV0000000000000000000000".to_string()),
            event: None,
            creator: "01LEAD000000000000000000000".to_string(),
            title: "Sunday MC".to_string(),
            edition: "classic".to_string(),
            raids: vec!["mc".to_string()],
            reserves_per_user: 2,
            per_item_cap: None,
            allow_duplicates: false,
            class_restriction: false,
            hidden: false,
            lock_at_event_start: false,
            locks_at: None,
            note: None,
            hard_reserves: vec![],
            locked: false,
            created_at: 1_000_000,
            edited_at: None,
        }
    }

    fn reserve(sheet_id: &str, user: &str, items: Vec<u32>) -> SoftResReserveRow {
        SoftResReserveRow {
            id: SoftResSheet::reserve_key(sheet_id, user),
            sheet: sheet_id.to_string(),
            user: user.to_string(),
            channel: "01CHAN000000000000000000000".to_string(),
            character_name: "Leeroy".to_string(),
            class: v0::WowClass::Paladin,
            items,
            note: None,
            plus_ones: 0,
            edited_at: 1_000_001,
        }
    }

    /// Install the unique indexes that enforce one-sheet-per-message and
    /// one-sheet-per-event on MongoDB.
    ///
    /// `database_test!` connects to a fresh database with no migrations
    /// run, so without this the Mongo driver would silently accept a
    /// duplicate event link and the guard would go untested. This spec
    /// MUST stay identical to the one in
    /// `admin_migrations/ops/mongodb/scripts.rs` (revision 66) and
    /// `init.rs`. The reference driver enforces the same rules in code,
    /// so it needs no setup.
    async fn create_softres_indexes(db: &crate::Database) {
        match db {
            crate::Database::Reference(_) => {}
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .db()
                    .run_command(bson::doc! {
                        "createIndexes": "softres_sheets",
                        "indexes": [
                            {
                                "key": { "message": 1_i32 },
                                "name": "message",
                                "unique": true
                            },
                            {
                                "key": { "event": 1_i32 },
                                "name": "event",
                                "unique": true,
                                "sparse": true
                            }
                        ]
                    })
                    .await
                    .expect("failed to create softres_sheets indexes");
            }
        }
    }

    #[tokio::test]
    async fn insert_fetch_and_event_lookup() {
        database_test!(|db| async move {
            let mut row = sheet("01SRS0000000000000000000000", "01MSG0000000000000000000000");
            row.event = Some("01EVT0000000000000000000000".to_string());
            db.insert_sheet(&row).await.unwrap();

            let fetched = db.fetch_sheet(&row.id).await.unwrap();
            assert_eq!(fetched.title, "Sunday MC");

            let bulk = db.fetch_sheets(&[row.id.clone()]).await.unwrap();
            assert_eq!(bulk.len(), 1);

            let by_event = db
                .fetch_sheet_by_event("01EVT0000000000000000000000")
                .await
                .unwrap();
            assert_eq!(by_event.map(|s| s.id), Some(row.id.clone()));

            assert_eq!(
                db.fetch_sheet_by_event("01EVT0000000000000000000001")
                    .await
                    .unwrap(),
                None
            );
        });
    }

    #[tokio::test]
    async fn duplicate_event_link_is_rejected() {
        database_test!(|db| async move {
            create_softres_indexes(&db).await;

            let event = "01EVT0000000000000000000002";
            let mut first = sheet("01SRS0000000000000000000010", "01MSG0000000000000000000010");
            first.event = Some(event.to_string());
            db.insert_sheet(&first).await.unwrap();

            // The double-link race: two creates validated the same event
            // concurrently — storage must reject the loser with the
            // mapped 409, never a bare database error.
            let mut second = sheet("01SRS0000000000000000000011", "01MSG0000000000000000000011");
            second.event = Some(event.to_string());
            let error = db
                .insert_sheet(&second)
                .await
                .expect_err("a second sheet on one event must be rejected");
            assert!(
                matches!(error.error_type, ErrorType::SoftResEventAlreadyLinked),
                "expected SoftResEventAlreadyLinked, got {:?}",
                error.error_type
            );
            assert!(db.fetch_sheet(&second.id).await.is_err());

            // Sparse index: any number of un-linked sheets coexist.
            let third = sheet("01SRS0000000000000000000012", "01MSG0000000000000000000012");
            let fourth = sheet("01SRS0000000000000000000013", "01MSG0000000000000000000013");
            db.insert_sheet(&third).await.unwrap();
            db.insert_sheet(&fourth).await.unwrap();
        });
    }

    #[tokio::test]
    async fn reserve_upsert_returns_previous_row() {
        database_test!(|db| async move {
            let row = sheet("01SRS0000000000000000000020", "01MSG0000000000000000000020");
            db.insert_sheet(&row).await.unwrap();

            let user = "01USER000000000000000000000";

            let previous = db
                .upsert_reserve(&reserve(&row.id, user, vec![17204]))
                .await
                .unwrap();
            assert!(previous.is_none());

            let previous = db
                .upsert_reserve(&reserve(&row.id, user, vec![18563, 18564]))
                .await
                .unwrap();
            assert_eq!(previous.map(|r| r.items), Some(vec![17204]));

            let fetched = db.fetch_reserve(&row.id, user).await.unwrap().unwrap();
            assert_eq!(fetched.items, vec![18563, 18564]);

            let removed = db.remove_reserve(&row.id, user).await.unwrap();
            assert_eq!(removed.map(|r| r.items), Some(vec![18563, 18564]));
            let removed = db.remove_reserve(&row.id, user).await.unwrap();
            assert!(removed.is_none());
        });
    }

    #[tokio::test]
    async fn item_counts_count_copies_and_exclude_the_given_user() {
        database_test!(|db| async move {
            let row = sheet("01SRS0000000000000000000030", "01MSG0000000000000000000030");
            db.insert_sheet(&row).await.unwrap();

            let alice = "01USERA00000000000000000000";
            let bob = "01USERB00000000000000000000";
            let carol = "01USERC00000000000000000000";

            // Bob holds TWO copies (duplicates allowed on some sheets) —
            // both must count toward the cap.
            db.upsert_reserve(&reserve(&row.id, alice, vec![17204]))
                .await
                .unwrap();
            db.upsert_reserve(&reserve(&row.id, bob, vec![17204, 17204]))
                .await
                .unwrap();
            db.upsert_reserve(&reserve(&row.id, carol, vec![18563]))
                .await
                .unwrap();

            assert_eq!(
                db.count_item_reservations(&row.id, 17204, "01USERZ00000000000000000000")
                    .await
                    .unwrap(),
                3
            );
            // Excluding bob removes both of his copies.
            assert_eq!(
                db.count_item_reservations(&row.id, 17204, bob).await.unwrap(),
                1
            );
            assert_eq!(
                db.count_item_reservations(&row.id, 99999, alice).await.unwrap(),
                0
            );

            let all = db.fetch_reserves_for_sheet(&row.id).await.unwrap();
            assert_eq!(all.len(), 3);
        });
    }

    #[tokio::test]
    async fn lock_is_exactly_once_and_unlock_clears_the_auto_lock() {
        database_test!(|db| async move {
            let mut row = sheet("01SRS0000000000000000000040", "01MSG0000000000000000000040");
            row.lock_at_event_start = true;
            row.locks_at = Some(2_000_000);
            db.insert_sheet(&row).await.unwrap();

            // First lock wins, second loses (manual lock racing the
            // event-cancel hook).
            assert!(db.set_sheet_locked_if_unlocked(&row.id).await.unwrap());
            assert!(!db.set_sheet_locked_if_unlocked(&row.id).await.unwrap());
            assert!(db.fetch_sheet(&row.id).await.unwrap().locked);

            // Unlock clears the flag, the snapshot AND the auto-lock
            // toggle: past the auto-lock instant the timestamp alone
            // would otherwise keep the sheet locked forever, and a
            // surviving toggle would advertise an auto-lock that can
            // never fire.
            db.set_sheet_unlocked(&row.id).await.unwrap();
            let fetched = db.fetch_sheet(&row.id).await.unwrap();
            assert!(!fetched.locked);
            assert_eq!(fetched.locks_at, None);
            assert!(!fetched.lock_at_event_start);
            assert!(!fetched.is_locked_now(3_000_000));
        });
    }

    #[tokio::test]
    async fn settings_update_never_touches_the_lock_flag() {
        database_test!(|db| async move {
            let row = sheet("01SRS0000000000000000000050", "01MSG0000000000000000000050");
            db.insert_sheet(&row).await.unwrap();

            // A lock lands between the edit route's fetch and its write.
            assert!(db.set_sheet_locked_if_unlocked(&row.id).await.unwrap());

            // The edit was validated against the PRE-lock fetch (locked:
            // false) — writing it must not resurrect an unlocked sheet.
            let mut edited = row.clone();
            edited.title = "Sunday MC (rescheduled)".to_string();
            edited.per_item_cap = Some(2);
            edited.note = Some("bring flasks".to_string());
            edited.edited_at = Some(1_500_000);
            db.update_sheet_settings(&edited).await.unwrap();

            let fetched = db.fetch_sheet(&row.id).await.unwrap();
            assert_eq!(fetched.title, "Sunday MC (rescheduled)");
            assert_eq!(fetched.per_item_cap, Some(2));
            assert_eq!(fetched.note.as_deref(), Some("bring flasks"));
            assert_eq!(fetched.edited_at, Some(1_500_000));
            assert!(fetched.locked, "edit clobbered a concurrent lock");

            // Clearing optional settings must unset them, not leave the
            // old values behind.
            let mut cleared = fetched.clone();
            cleared.per_item_cap = None;
            cleared.note = None;
            db.update_sheet_settings(&cleared).await.unwrap();
            let fetched = db.fetch_sheet(&row.id).await.unwrap();
            assert_eq!(fetched.per_item_cap, None);
            assert_eq!(fetched.note, None);
        });
    }

    #[tokio::test]
    async fn cascades_remove_sheets_and_reserves() {
        database_test!(|db| async move {
            // Message cascade
            let row = sheet("01SRS0000000000000000000060", "01MSG0000000000000000000060");
            db.insert_sheet(&row).await.unwrap();
            db.upsert_reserve(&reserve(&row.id, "01USERA00000000000000000000", vec![17204]))
                .await
                .unwrap();
            db.delete_softres_for_messages(&[row.message.clone()])
                .await
                .unwrap();
            assert!(db.fetch_sheet(&row.id).await.is_err());
            assert!(db
                .fetch_reserve(&row.id, "01USERA00000000000000000000")
                .await
                .unwrap()
                .is_none());

            // Channel cascade
            let row = sheet("01SRS0000000000000000000061", "01MSG0000000000000000000061");
            db.insert_sheet(&row).await.unwrap();
            db.upsert_reserve(&reserve(&row.id, "01USERB00000000000000000000", vec![18563]))
                .await
                .unwrap();
            db.delete_softres_for_channel(&row.channel).await.unwrap();
            assert!(db.fetch_sheet(&row.id).await.is_err());
            assert!(db
                .fetch_reserve(&row.id, "01USERB00000000000000000000")
                .await
                .unwrap()
                .is_none());

            // Server cascade (reserve rows carry no server id — the
            // implementation must resolve them via the sheets).
            let row = sheet("01SRS0000000000000000000062", "01MSG0000000000000000000062");
            db.insert_sheet(&row).await.unwrap();
            db.upsert_reserve(&reserve(&row.id, "01USERC00000000000000000000", vec![19019]))
                .await
                .unwrap();
            db.delete_softres_for_server(row.server.as_deref().unwrap())
                .await
                .unwrap();
            assert!(db.fetch_sheet(&row.id).await.is_err());
            assert!(db
                .fetch_reserve(&row.id, "01USERC00000000000000000000")
                .await
                .unwrap()
                .is_none());
        });
    }
}
