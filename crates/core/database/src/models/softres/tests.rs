//! S4 protect and history-wipe helpers (7.4 "S4", 7.2 "S4"):
//! `SoftResSheet::close_open_for_channel` and
//! `SoftResSheet::delete_for_messages`.

use revolt_models::v0;

use crate::{SoftResReserveRow, SoftResSheet};

const CHAN_A: &str = "01CHANA0000000000000000000";
const CHAN_B: &str = "01CHANB0000000000000000000";
const USER_1: &str = "01USER10000000000000000000";
const USER_2: &str = "01USER20000000000000000000";

fn sheet(id: &str, message: &str, channel: &str, locked: bool) -> SoftResSheet {
    SoftResSheet {
        id: id.to_string(),
        message: message.to_string(),
        channel: channel.to_string(),
        server: Some("01SRV00000000000000000000".to_string()),
        event: None,
        creator: "01LEAD0000000000000000000".to_string(),
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
        note: Some("bring flasks".to_string()),
        hard_reserves: vec![],
        locked,
        created_at: 1_000_000,
        edited_at: None,
    }
}

fn reserve(sheet: &SoftResSheet, user: &str) -> SoftResReserveRow {
    SoftResReserveRow {
        id: SoftResSheet::reserve_key(&sheet.id, user),
        sheet: sheet.id.clone(),
        user: user.to_string(),
        channel: sheet.channel.clone(),
        character_name: "Leeroy".to_string(),
        class: v0::WowClass::Paladin,
        items: vec![17204],
        note: None,
        plus_ones: 0,
        edited_at: 1_000_001,
    }
}

fn locked(sheet: &SoftResSheet) -> SoftResSheet {
    let mut sheet = sheet.clone();
    sheet.locked = true;
    sheet
}

fn reserve_ids(rows: &[SoftResReserveRow]) -> Vec<String> {
    let mut ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
    ids.sort();
    ids
}

/// Channel A: two open sheets, a sheet past its `locks_at` that was never
/// flagged (reads as locked, stored as open), and a flagged sheet. Channel
/// B: one open and one flagged sheet. Ids ascend in the order returned.
struct Fixture {
    a_open_1: SoftResSheet,
    a_auto: SoftResSheet,
    a_locked: SoftResSheet,
    a_open_2: SoftResSheet,
    b_open: SoftResSheet,
    b_locked: SoftResSheet,
}

impl Fixture {
    fn new() -> Self {
        let mut a_auto = sheet(
            "01SRSA2000000000000000000",
            "01MSGA2000000000000000000",
            CHAN_A,
            false,
        );
        a_auto.lock_at_event_start = true;
        a_auto.locks_at = Some(1);
        Fixture {
            a_open_1: sheet(
                "01SRSA1000000000000000000",
                "01MSGA1000000000000000000",
                CHAN_A,
                false,
            ),
            a_auto,
            a_locked: sheet(
                "01SRSA3000000000000000000",
                "01MSGA3000000000000000000",
                CHAN_A,
                true,
            ),
            a_open_2: sheet(
                "01SRSA4000000000000000000",
                "01MSGA4000000000000000000",
                CHAN_A,
                false,
            ),
            b_open: sheet(
                "01SRSB1000000000000000000",
                "01MSGB1000000000000000000",
                CHAN_B,
                false,
            ),
            b_locked: sheet(
                "01SRSB2000000000000000000",
                "01MSGB2000000000000000000",
                CHAN_B,
                true,
            ),
        }
    }

    fn all(&self) -> [&SoftResSheet; 6] {
        [
            &self.a_open_1,
            &self.a_auto,
            &self.a_locked,
            &self.a_open_2,
            &self.b_open,
            &self.b_locked,
        ]
    }
}

#[tokio::test]
async fn open_sheet_scan_is_scoped_to_the_channel_and_skips_locked_sheets() {
    database_test!(|db| async move {
        let f = Fixture::new();
        assert!(f.a_auto.is_locked_now(2), "fixture: a_auto reads as locked");
        for row in f.all() {
            db.insert_sheet(row).await.unwrap();
        }

        assert_eq!(
            db.fetch_open_sheet_ids_for_channel(CHAN_A).await.unwrap(),
            vec![
                f.a_open_1.id.clone(),
                f.a_auto.id.clone(),
                f.a_open_2.id.clone()
            ]
        );
        assert_eq!(
            db.fetch_open_sheet_ids_for_channel(CHAN_B).await.unwrap(),
            vec![f.b_open.id.clone()]
        );
        assert!(db
            .fetch_open_sheet_ids_for_channel("01CHANC0000000000000000000")
            .await
            .unwrap()
            .is_empty());
    });
}

#[tokio::test]
async fn close_open_for_channel_locks_only_that_channels_open_sheets() {
    database_test!(|db| async move {
        let f = Fixture::new();
        for row in f.all() {
            db.insert_sheet(row).await.unwrap();
        }
        let a_row = reserve(&f.a_open_1, USER_1);
        let b_row = reserve(&f.b_open, USER_1);
        db.upsert_reserve(&a_row).await.unwrap();
        db.upsert_reserve(&b_row).await.unwrap();

        let closed = SoftResSheet::close_open_for_channel(&db, CHAN_A)
            .await
            .unwrap();
        assert_eq!(
            closed,
            vec![
                f.a_open_1.id.clone(),
                f.a_auto.id.clone(),
                f.a_open_2.id.clone()
            ]
        );

        // Only the flag moved: the auto-lock snapshot and every setting are
        // kept, so the rows equal the fixture with `locked` set.
        for row in [&f.a_open_1, &f.a_auto, &f.a_open_2] {
            assert_eq!(db.fetch_sheet(&row.id).await.unwrap(), locked(row));
        }

        // The already-locked sheet and the other channel are untouched.
        assert_eq!(db.fetch_sheet(&f.a_locked.id).await.unwrap(), f.a_locked);
        assert_eq!(db.fetch_sheet(&f.b_open.id).await.unwrap(), f.b_open);
        assert_eq!(db.fetch_sheet(&f.b_locked.id).await.unwrap(), f.b_locked);

        // Closing keeps the reserves.
        assert_eq!(
            db.fetch_reserve(&f.a_open_1.id, USER_1).await.unwrap(),
            Some(a_row)
        );
        assert_eq!(
            db.fetch_reserve(&f.b_open.id, USER_1).await.unwrap(),
            Some(b_row)
        );

        // A second run finds nothing open and returns nothing.
        assert!(db
            .fetch_open_sheet_ids_for_channel(CHAN_A)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            SoftResSheet::close_open_for_channel(&db, CHAN_A)
                .await
                .unwrap(),
            Vec::<String>::new()
        );

        // The other channel's run returns exactly its own open sheet.
        assert_eq!(
            SoftResSheet::close_open_for_channel(&db, CHAN_B)
                .await
                .unwrap(),
            vec![f.b_open.id.clone()]
        );
        assert_eq!(
            db.fetch_sheet(&f.b_open.id).await.unwrap(),
            locked(&f.b_open)
        );
    });
}

#[tokio::test]
async fn close_listed_skips_a_sheet_locked_after_the_scan() {
    database_test!(|db| async move {
        let first = sheet(
            "01SRSC1000000000000000000",
            "01MSGC1000000000000000000",
            CHAN_A,
            false,
        );
        let second = sheet(
            "01SRSC2000000000000000000",
            "01MSGC2000000000000000000",
            CHAN_A,
            false,
        );
        db.insert_sheet(&first).await.unwrap();
        db.insert_sheet(&second).await.unwrap();

        let snapshot = db.fetch_open_sheet_ids_for_channel(CHAN_A).await.unwrap();
        assert_eq!(snapshot, vec![first.id.clone(), second.id.clone()]);

        // The lock route (or the event-cancel hook) wins `second` between
        // the scan and the flip; it published, so this call must not.
        assert!(db.set_sheet_locked_if_unlocked(&second.id).await.unwrap());

        assert_eq!(
            SoftResSheet::close_listed(&db, &snapshot).await,
            vec![first.id.clone()]
        );
        assert_eq!(db.fetch_sheet(&first.id).await.unwrap(), locked(&first));
        assert_eq!(db.fetch_sheet(&second.id).await.unwrap(), locked(&second));

        // Everything is locked now: the same list closes nothing.
        assert_eq!(
            SoftResSheet::close_listed(&db, &snapshot).await,
            Vec::<String>::new()
        );
    });
}

#[tokio::test]
async fn delete_for_messages_removes_only_the_listed_sheets_and_reserves() {
    database_test!(|db| async move {
        let gone_open = sheet(
            "01SRSD1000000000000000000",
            "01MSGD1000000000000000000",
            CHAN_A,
            false,
        );
        let gone_locked = sheet(
            "01SRSD2000000000000000000",
            "01MSGD2000000000000000000",
            CHAN_A,
            true,
        );
        let kept_same_channel = sheet(
            "01SRSD3000000000000000000",
            "01MSGD3000000000000000000",
            CHAN_A,
            false,
        );
        let kept_other_channel = sheet(
            "01SRSD4000000000000000000",
            "01MSGD4000000000000000000",
            CHAN_B,
            false,
        );
        let all = [
            &gone_open,
            &gone_locked,
            &kept_same_channel,
            &kept_other_channel,
        ];
        for row in all {
            db.insert_sheet(row).await.unwrap();
            db.upsert_reserve(&reserve(row, USER_1)).await.unwrap();
            db.upsert_reserve(&reserve(row, USER_2)).await.unwrap();
        }

        // An empty list deletes nothing.
        SoftResSheet::delete_for_messages(&db, &[]).await.unwrap();
        for row in all {
            assert_eq!(&db.fetch_sheet(&row.id).await.unwrap(), row);
            assert_eq!(db.fetch_reserves_for_sheet(&row.id).await.unwrap().len(), 2);
        }

        SoftResSheet::delete_for_messages(
            &db,
            &[
                gone_open.message.clone(),
                gone_locked.message.clone(),
                "01MSGNOSHEET0000000000000".to_string(),
            ],
        )
        .await
        .unwrap();

        for row in [&gone_open, &gone_locked] {
            assert!(db.fetch_sheet(&row.id).await.is_err());
            assert!(db
                .fetch_reserves_for_sheet(&row.id)
                .await
                .unwrap()
                .is_empty());
            assert_eq!(db.fetch_reserve(&row.id, USER_1).await.unwrap(), None);
            assert_eq!(db.fetch_reserve(&row.id, USER_2).await.unwrap(), None);
        }

        for row in [&kept_same_channel, &kept_other_channel] {
            assert_eq!(&db.fetch_sheet(&row.id).await.unwrap(), row);
            assert_eq!(
                reserve_ids(&db.fetch_reserves_for_sheet(&row.id).await.unwrap()),
                vec![
                    SoftResSheet::reserve_key(&row.id, USER_1),
                    SoftResSheet::reserve_key(&row.id, USER_2)
                ]
            );
            assert_eq!(
                db.fetch_reserve(&row.id, USER_1).await.unwrap(),
                Some(reserve(row, USER_1))
            );
        }
    });
}

/// MongoDB only (the Reference driver stores typed rows): a sheet row that
/// no longer decodes as a `SoftResSheet` is still deleted with its
/// reserves, so the history wipe cannot leave a title or note behind.
#[tokio::test]
async fn delete_for_messages_removes_a_sheet_row_that_does_not_decode() {
    database_test!(|db| async move {
        #[cfg(feature = "mongodb")]
        {
            if let crate::Database::MongoDb(mongo) = &db {
                let id = "01SRSE1000000000000000000";
                let message = "01MSGE1000000000000000000";
                let raw = mongo.col::<bson::Document>("softres_sheets");
                raw.insert_one(bson::doc! {
                    "_id": id,
                    "message": message,
                    "channel": CHAN_A,
                    "title": "Sunday MC",
                    "raids": "not a list"
                })
                .await
                .unwrap();
                // Proof of the fixture: the typed read cannot decode it.
                assert!(mongo
                    .col::<SoftResSheet>("softres_sheets")
                    .find_one(bson::doc! { "_id": id })
                    .await
                    .is_err());

                let stub = sheet(id, message, CHAN_A, false);
                db.upsert_reserve(&reserve(&stub, USER_1)).await.unwrap();

                SoftResSheet::delete_for_messages(&db, &[message.to_string()])
                    .await
                    .unwrap();

                assert!(raw
                    .find_one(bson::doc! { "_id": id })
                    .await
                    .unwrap()
                    .is_none());
                assert!(db.fetch_reserves_for_sheet(id).await.unwrap().is_empty());
            }
        }
    });
}
