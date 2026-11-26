use revolt_models::v0::{MessageSort, ReportedMessageSnapshot};
use revolt_result::{ErrorType, Result};

use crate::{
    Database, Message, MessageFilter, MessageQuery, MessageTimePeriod, ProtectedReadView, Server,
    User,
};

auto_derived!(
    /// Snapshot of some content
    pub struct Snapshot {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Report parent Id
        pub report_id: String,
        /// Snapshot of content
        pub content: SnapshotContent,
    }

    /// Enum to map into different models
    /// that can be saved in a snapshot
    #[serde(tag = "_type")]
    pub enum SnapshotContent {
        Message {
            /// Context before the message
            #[serde(rename = "_prior_context", default)]
            prior_context: Vec<Message>,

            /// Context after the message
            #[serde(rename = "_leading_context", default)]
            leading_context: Vec<Message>,

            /// Message
            #[serde(flatten)]
            message: Message,
        },
        Server(Server),
        User(User),
        /// Copy of the reported message supplied by the reporter's client;
        /// stands alone so reports work for conversations the server cannot
        /// read (end-to-end encrypted DMs)
        ReporterMessage {
            /// The reported message as seen on the reporter's device
            message: ReportedMessageSnapshot,

            /// Surrounding messages supplied by the reporter, ordered by id
            #[serde(default)]
            context: Vec<ReportedMessageSnapshot>,
        },
    }
);

/// Drop every row `view` does not serve (the backstop behind the query
/// filter), reporting each TRUE stray by ids only; a wipe-pending drop is
/// never reported (design 7.5 "S4")
fn retain_servable(messages: &mut Vec<Message>, view: &ProtectedReadView) {
    Message::retain_servable(messages, view, report_dropped_row);
}

/// The read view a row of `channel_id` is judged by: the channel's own, or
/// for a thread its parent's (the permission target, #182). `None` when
/// either is missing (W2 audit B3); any other read error as is.
async fn message_read_view(db: &Database, channel_id: &str) -> Result<Option<ProtectedReadView>> {
    let channel = match db.fetch_channel(channel_id).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    match channel.permission_target(db).await {
        Ok(target) => Ok(Some(ProtectedReadView::of_read_target(&channel, &target))),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Report a row left out of a safety snapshot (ids only)
fn report_dropped_row(message: &Message) {
    revolt_config::capture_message(
        &format!(
            "Dropped a plaintext row from a safety snapshot of protected channel {} (message {})",
            message.channel, message.id
        ),
        revolt_config::Level::Error,
    );
}

impl SnapshotContent {
    /// Generate snapshot from a given message
    ///
    /// Every row the channel's read view does not serve (design 7.5 "S4":
    /// in a protected channel, plaintext above the boundary B, any plaintext
    /// without one, and every plaintext row once a wipe is requested) is left
    /// out of both context lists, and such a REPORTED message gives `None`,
    /// so no snapshot embeds one and none of its attachments are returned.
    /// Pre-boundary plaintext of a channel protected with its history is
    /// served. Ciphertext rows are kept as stored. A thread's rows are
    /// judged by its parent. A channel (or thread parent) that no longer
    /// exists gives `None` too; any other failed channel read is an error,
    /// never a snapshot with unfiltered rows.
    pub async fn generate_from_message(
        db: &Database,
        message: Message,
    ) -> Result<Option<(SnapshotContent, Vec<String>)>> {
        // The view the context queries filter by, so each list is full
        // around an unservable row. A channel (or a thread's parent) that
        // no longer exists gives no server copy, like a stray (W2 audit B3):
        // the report is still filed without it.
        let Some(query_view) = message_read_view(db, &message.channel).await? else {
            return Ok(None);
        };

        // Collect prior context
        let mut prior_context = db
            .fetch_servable_messages(
                MessageQuery {
                    filter: MessageFilter {
                        channel: Some(message.channel.to_string()),
                        ..Default::default()
                    },
                    limit: Some(15),
                    time_period: MessageTimePeriod::Absolute {
                        before: Some(message.id.to_string()),
                        after: None,
                        sort: Some(MessageSort::Latest),
                    },
                },
                &query_view,
            )
            .await?;

        // Collect leading context
        let mut leading_context = db
            .fetch_servable_messages(
                MessageQuery {
                    filter: MessageFilter {
                        channel: Some(message.channel.to_string()),
                        ..Default::default()
                    },
                    limit: Some(15),
                    time_period: MessageTimePeriod::Absolute {
                        before: None,
                        after: Some(message.id.to_string()),
                        sort: Some(MessageSort::Oldest),
                    },
                },
                &query_view,
            )
            .await?;

        // Read the view again after every row it judges (the reported
        // message was read by the caller), and judge every row by this one:
        // protect, the boundary and the wipe are one-way, so a view read
        // later never serves a row an earlier one refused, and a protect or
        // a wipe request landing after the first read cannot let a stray or
        // a wipe-pending row into the snapshot. A thread is judged by its
        // parent (W2 audit B1).
        let Some(view) = message_read_view(db, &message.channel).await? else {
            return Ok(None);
        };
        if !message.is_servable(&view) {
            if message.is_stray(&view) {
                report_dropped_row(&message);
            }
            return Ok(None);
        }

        retain_servable(&mut prior_context, &view);
        retain_servable(&mut leading_context, &view);

        // Collect message attachments
        let files = message
            .attachments
            .as_ref()
            .map(|attachments| attachments.iter().map(|x| x.id.to_string()).collect())
            .unwrap_or_default();

        Ok(Some((
            SnapshotContent::Message {
                message,
                prior_context,
                leading_context,
            },
            files,
        )))
    }

    /// Generate snapshot from a given server
    pub fn generate_from_server(server: Server) -> Result<(SnapshotContent, Vec<String>)> {
        // Collect server's icon and banner
        let files = [&server.icon, &server.banner]
            .iter()
            .filter_map(|x| x.as_ref().map(|x| x.id.to_string()))
            .collect();

        Ok((SnapshotContent::Server(server), files))
    }

    /// Generate snapshot from a given user
    pub fn generate_from_user(mut user: User) -> Result<(SnapshotContent, Vec<String>)> {
        // Collect user's avatar and profile background
        let files = [
            user.avatar.as_ref(),
            user.profile
                .as_ref()
                .and_then(|profile| profile.background.as_ref()),
        ]
        .iter()
        .filter_map(|x| x.as_ref().map(|x| x.id.to_string()))
        .collect();

        // Strip donation and referral state; it is not moderation evidence
        // and must not outlive the account's own deletion
        user.supporter = None;
        user.referral_count = None;
        user.referral_pending = None;
        user.welcomed_at = None;

        // Strip the anti-spam pause record; it is private to the server and
        // its fingerprint and report id must never reach a report snapshot
        user.dm_guard = None;

        Ok((SnapshotContent::User(user), files))
    }
}

#[cfg(test)]
mod tests {
    use iso8601_timestamp::Timestamp;

    use crate::{Channel, Database, DmGuard, EncryptedPayload, Message, SnapshotContent, User};

    #[test]
    fn generate_from_user_strips_dm_guard() {
        let user = User {
            id: ulid::Ulid::new().to_string(),
            username: "spammer".to_string(),
            discriminator: "0001".to_string(),
            dm_guard: Some(DmGuard {
                report_id: "01REPORT00000000000000000000".to_string(),
                flagged_at: Timestamp::now_utc(),
                paused: true,
                cleared_at: None,
                recipients: 3,
                fingerprint: "fingerprint".to_string(),
            }),
            ..Default::default()
        };

        let (content, files) = SnapshotContent::generate_from_user(user.clone()).unwrap();
        assert!(files.is_empty());

        match content {
            SnapshotContent::User(snapshot_user) => {
                assert_eq!(snapshot_user.id, user.id);
                assert!(snapshot_user.dm_guard.is_none());
            }
            content => panic!("expected a user snapshot, got {content:?}"),
        }
    }

    /// Design 5.6 vector payload
    const PAYLOAD_JSON: &str = r#"{"v":1,"group_id":"4a4ba4afc6e6ea1c9f4a271f7eded44ea860fdb814e4e1377121e02635a715b5","epoch":7,"sender_device_id":"ffeeddccbbaa99887766554433221100","nonce":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3","ciphertext":"7lyFR0kjzwme2lNYYODt2rZmmYbNUdZ30V/L+qdgbzKONjAeYv8uelDf4K/WcWB+eZH5NVTNV+9i0rW+AGfyD6wMllEfcDpoWSemybsLAnUd2vkx5tmdCrhnWkKmIt4AYuiW2wJroVo6I6KRe9NVyjAYMDwcOtyPnYobI5CPNwg3O7QjdMMjhdkjNGEVh4oGVS+nI04P","sig":"Ylo7oNHshb/EPJ67afoJrw2H0t6FKRiM3dDOUbHGchXCtq3AqxJLv0GuR87KNu8msVg2nKn3iVs4OCDOu15MAA"}"#;

    const SERVER: &str = "01JB0SNAPSERVER00000000000";
    const PROTECTED_CHANNEL: &str = "01JB0SNAPPR0TECTED00000000";
    const OPEN_CHANNEL: &str = "01JB0SNAP0PEN0000000000000";
    const MISSING_CHANNEL: &str = "01JB0SNAPM1SS1NG0000000000";
    const AUTHOR: &str = "01HZXBBBBBBBBBBBBBBBBBBBBB";

    // One channel's rows, oldest first; `REPORTED` is the reported message
    const PRIOR_STRAY: &str = "01JB0000000000000000000001";
    const PRIOR_CIPHERTEXT: &str = "01JB0000000000000000000002";
    const REPORTED: &str = "01JB0000000000000000000003";
    const LEADING_CIPHERTEXT: &str = "01JB0000000000000000000004";
    const LEADING_STRAY: &str = "01JB0000000000000000000005";

    fn text_channel(id: &str, protected: bool) -> Channel {
        serde_json::from_value(serde_json::json!({
            "channel_type": "TextChannel",
            "_id": id,
            "server": SERVER,
            "name": "general",
            "protected": protected,
        }))
        .expect("text channel")
    }

    fn payload() -> EncryptedPayload {
        serde_json::from_str(PAYLOAD_JSON).expect("5.6 payload_json deserializes")
    }

    fn plaintext_row(id: &str, channel: &str) -> Message {
        Message {
            id: id.to_string(),
            channel: channel.to_string(),
            author: AUTHOR.to_string(),
            content: Some("hi".to_string()),
            ..Default::default()
        }
    }

    fn ciphertext_row(id: &str, channel: &str) -> Message {
        Message {
            id: id.to_string(),
            nonce: Some(id.to_string()),
            channel: channel.to_string(),
            author: AUTHOR.to_string(),
            flags: Some(0),
            encrypted: Some(payload()),
            ..Default::default()
        }
    }

    /// Write a row past `insert_message`'s refusal, as the R15 compensation
    /// window can leave one
    async fn insert_raw(db: &Database, message: &Message) {
        match db {
            Database::Reference(reference) => {
                reference
                    .messages
                    .lock()
                    .await
                    .insert(message.id.clone(), message.clone());
            }
            #[cfg(feature = "mongodb")]
            Database::MongoDb(mongo) => {
                mongo
                    .col::<Message>("messages")
                    .insert_one(message)
                    .await
                    .expect("raw row");
            }
        }
    }

    /// The five rows of `channel`: in a protected one the two strays are
    /// raw plaintext rows and the rest ciphertext, in an open one all are
    /// plaintext
    async fn seed(db: &Database, channel: &str, protected: bool) {
        db.insert_channel(&text_channel(channel, protected))
            .await
            .expect("channel");

        for id in [PRIOR_STRAY, LEADING_STRAY] {
            let row = plaintext_row(id, channel);
            if protected {
                insert_raw(db, &row).await;
            } else {
                db.insert_message(&row).await.expect("plaintext row");
            }
        }

        for id in [PRIOR_CIPHERTEXT, REPORTED, LEADING_CIPHERTEXT] {
            let row = if protected {
                ciphertext_row(id, channel)
            } else {
                plaintext_row(id, channel)
            };
            db.insert_message(&row).await.expect("row");
        }
    }

    /// Reported id, prior context ids and leading context ids, in snapshot
    /// order
    fn snapshot_ids(snapshot: &SnapshotContent) -> (String, Vec<String>, Vec<String>) {
        let SnapshotContent::Message {
            message,
            prior_context,
            leading_context,
        } = snapshot
        else {
            panic!("a message snapshot");
        };
        let ids = |rows: &Vec<Message>| rows.iter().map(|row| row.id.clone()).collect();
        (message.id.clone(), ids(prior_context), ids(leading_context))
    }

    /// R15 backstop, decision 9 (W2) [R#4]: in a protected channel both
    /// context lists drop the plaintext rows and keep the ciphertext rows as
    /// stored. Only the older stray is reachable through R15 (strays predate
    /// protect); the newer one proves the leading list is filtered too.
    #[tokio::test]
    async fn protected_snapshot_drops_stray_context_rows() {
        database_test!(|db| async move {
            seed(&db, PROTECTED_CHANNEL, true).await;

            let reported = db.fetch_message(REPORTED).await.expect("reported row");
            let (snapshot, files) = SnapshotContent::generate_from_message(&db, reported)
                .await
                .expect("snapshot")
                .expect("a ciphertext row is servable");

            assert_eq!(
                snapshot_ids(&snapshot),
                (
                    REPORTED.to_string(),
                    vec![PRIOR_CIPHERTEXT.to_string()],
                    vec![LEADING_CIPHERTEXT.to_string()],
                ),
                "the strays are dropped, the ciphertext rows kept"
            );
            assert!(files.is_empty());

            let SnapshotContent::Message {
                message,
                prior_context,
                leading_context,
            } = &snapshot
            else {
                unreachable!();
            };
            for row in std::iter::once(message)
                .chain(prior_context)
                .chain(leading_context)
            {
                assert_eq!(row.encrypted, Some(payload()), "{} kept as stored", row.id);
            }
        });
    }

    /// A stray plaintext row as the REPORTED message gives no snapshot at all
    #[tokio::test]
    async fn stray_reported_message_gives_no_snapshot() {
        database_test!(|db| async move {
            seed(&db, PROTECTED_CHANNEL, true).await;

            let stray = db.fetch_message(PRIOR_STRAY).await.expect("raw stray row");
            assert!(stray.content.is_some(), "the driver still reads the stray");
            let snapshot = SnapshotContent::generate_from_message(&db, stray)
                .await
                .expect("a stray is not an error");
            assert!(snapshot.is_none(), "no snapshot embeds the stray");
        });
    }

    /// Positive control: an unprotected channel's snapshot keeps every
    /// plaintext row, newest first before and oldest first after
    #[tokio::test]
    async fn unprotected_snapshot_keeps_every_row() {
        database_test!(|db| async move {
            seed(&db, OPEN_CHANNEL, false).await;

            let reported = db.fetch_message(REPORTED).await.expect("reported row");
            let (snapshot, _) = SnapshotContent::generate_from_message(&db, reported)
                .await
                .expect("snapshot")
                .expect("an open channel serves every row");

            assert_eq!(
                snapshot_ids(&snapshot),
                (
                    REPORTED.to_string(),
                    vec![PRIOR_CIPHERTEXT.to_string(), PRIOR_STRAY.to_string()],
                    vec![LEADING_CIPHERTEXT.to_string(), LEADING_STRAY.to_string()],
                )
            );
        });
    }

    /// The view every row is judged by is read AFTER both context fetches
    /// and before any row is judged. Protect, the boundary and the wipe are
    /// one-way, so a view read after the rows cannot serve a row read under
    /// a stricter one; read only first, a protect or a wipe request landing
    /// in between would let a stray or a wipe-pending row into the snapshot.
    /// The view the two fetches filter by (S4-PA-15) is a separate read made
    /// BEFORE them, and only shapes the queries. No fault injection can land
    /// a protect between two awaits, hence source order. (W2 audit B1/B3:
    /// the read also reads a thread's parent and its `NotFound` gives
    /// `None`. S4: the flag became `message_read_view`, read twice.)
    #[test]
    fn channel_flag_is_read_after_the_rows_it_judges() {
        let source = include_str!("model.rs");
        let start = source
            .find("pub async fn generate_from_message(")
            .expect("generate_from_message");
        let end = start
            + source[start..]
                .find("pub fn generate_from_server(")
                .expect("generate_from_server");
        let body = &source[start..end];

        let fetches: Vec<usize> = body
            .match_indices(".fetch_servable_messages(")
            .map(|(at, _)| at)
            .collect();
        assert_eq!(fetches.len(), 2, "two context fetches");
        assert_eq!(
            body.matches(".fetch_messages(").count(),
            0,
            "no unfiltered fetch"
        );
        assert_eq!(
            body.matches("&query_view,").count(),
            2,
            "both fetches filter"
        );
        let query_view = body
            .find("let Some(query_view) = message_read_view(db, &message.channel).await? else {")
            .expect("the query view read");
        let flag = body
            .find("let Some(view) = message_read_view(db, &message.channel).await? else {")
            .expect("the flag read");
        assert_eq!(body.matches("message_read_view(").count(), 2);
        assert_eq!(body.matches(".fetch_channel(").count(), 0);
        let judged = [
            "if !message.is_servable(&view) {",
            "retain_servable(&mut prior_context, &view);",
            "retain_servable(&mut leading_context, &view);",
        ]
        .map(|needle| body.find(needle).expect(needle));

        assert!(
            fetches.iter().all(|&fetch| query_view < fetch),
            "the query view is read before both fetches"
        );
        assert!(
            fetches.iter().all(|&fetch| fetch < flag),
            "the flag is read after both fetches"
        );
        assert!(
            judged.iter().all(|&at| flag < at),
            "every row is judged after the flag read"
        );
        assert_eq!(body.matches("is_servable(").count(), 1, "one judgment");
        assert_eq!(body.matches("retain_servable(").count(), 2);
    }

    /// W2 audit B3: a message whose channel no longer exists gives no
    /// server copy (`None`, as a stray does) instead of failing the report;
    /// so does a thread whose parent is gone. This used to be an error
    /// (`NotFound`), which failed the whole user report. Any other failed
    /// channel read is still an error; an undecodable channel row cannot
    /// stand in for one here (debug builds unwrap inside `query!`).
    ///
    /// Control: the `NotFound` arm removed (the `2acdf5f0` read with `?`) →
    /// `generate_from_message` errors.
    #[tokio::test]
    async fn missing_channel_gives_no_snapshot() {
        database_test!(|db| async move {
            for id in [PRIOR_STRAY, REPORTED, LEADING_STRAY] {
                insert_raw(&db, &plaintext_row(id, MISSING_CHANNEL)).await;
            }
            db.insert_channel(&thread(PARENTLESS_THREAD, MISSING_CHANNEL))
                .await
                .expect("thread");
            insert_raw(&db, &plaintext_row(THREAD_ROW, PARENTLESS_THREAD)).await;

            for id in [REPORTED, THREAD_ROW] {
                let reported = db.fetch_message(id).await.expect("reported row");
                let snapshot = SnapshotContent::generate_from_message(&db, reported)
                    .await
                    .unwrap_or_else(|error| panic!("{id}: not an error: {error:?}"));
                assert!(snapshot.is_none(), "{id}: no channel, no server copy");
            }
        });
    }

    /// W2 audit B1: a thread's rows are judged by its parent, so a thread
    /// left under a protected parent snapshots no plaintext row; a thread
    /// under an open parent keeps its rows (positive control)
    ///
    /// Control: the flag read on the thread itself (no `permission_target`)
    /// → the orphan's stray is snapshotted.
    #[tokio::test]
    async fn thread_rows_are_judged_by_the_parent() {
        database_test!(|db| async move {
            db.insert_channel(&text_channel(PROTECTED_CHANNEL, true))
                .await
                .expect("protected parent");
            db.insert_channel(&text_channel(OPEN_CHANNEL, false))
                .await
                .expect("open parent");
            db.insert_channel(&thread(ORPHAN_THREAD, PROTECTED_CHANNEL))
                .await
                .expect("orphan thread");
            db.insert_channel(&thread(OPEN_THREAD, OPEN_CHANNEL))
                .await
                .expect("open thread");

            insert_raw(&db, &plaintext_row(THREAD_ROW, ORPHAN_THREAD)).await;
            let stray = db.fetch_message(THREAD_ROW).await.expect("raw stray row");
            let snapshot = SnapshotContent::generate_from_message(&db, stray)
                .await
                .expect("a stray is not an error");
            assert!(snapshot.is_none(), "no snapshot embeds the orphan's stray");

            let open_row = plaintext_row(OPEN_THREAD_ROW, OPEN_THREAD);
            db.insert_message(&open_row).await.expect("plaintext row");
            let (snapshot, _) = SnapshotContent::generate_from_message(&db, open_row)
                .await
                .expect("snapshot")
                .expect("an open parent serves the thread's rows");
            assert_eq!(snapshot_ids(&snapshot).0, OPEN_THREAD_ROW);
        });
    }

    const HISTORY_CHANNEL: &str = "01JB0SNAPH1ST0RY0000000000";
    const FULL_CHANNEL: &str = "01JB0SNAPC0NTEXT0000000000";

    /// A protected channel holding its pre-protect history: boundary
    /// `boundary`, the wipe state `wipe` (its JSON)
    fn history_channel(id: &str, boundary: &str, wipe: serde_json::Value) -> Channel {
        serde_json::from_value(serde_json::json!({
            "channel_type": "TextChannel",
            "_id": id,
            "server": SERVER,
            "name": "general",
            "protected": true,
            "protected_history": { "boundary": boundary, "wipe": wipe },
        }))
        .expect("text channel with history")
    }

    fn wipe_none() -> serde_json::Value {
        serde_json::json!({ "state": "none" })
    }

    fn wipe_requested() -> serde_json::Value {
        serde_json::json!({ "state": "requested", "at": "2026-11-18T00:00:00.000Z", "by": AUTHOR })
    }

    /// The five rows of `seed` in `HISTORY_CHANNEL`, protected with B =
    /// `PRIOR_STRAY` (a pre-protect plaintext row at the boundary) and
    /// `wipe`; `LEADING_STRAY` is a stray above B
    async fn seed_history(db: &Database, wipe: serde_json::Value) {
        let channel = history_channel(HISTORY_CHANNEL, PRIOR_STRAY, wipe);
        db.insert_channel(&channel).await.expect("channel");
        for id in [PRIOR_STRAY, LEADING_STRAY] {
            insert_raw(db, &plaintext_row(id, HISTORY_CHANNEL)).await;
        }
        for id in [PRIOR_CIPHERTEXT, REPORTED, LEADING_CIPHERTEXT] {
            db.insert_message(&ciphertext_row(id, HISTORY_CHANNEL))
                .await
                .expect("ciphertext row");
        }
    }

    async fn snapshot_of(db: &Database, id: &str) -> Option<(String, Vec<String>, Vec<String>)> {
        let reported = db.fetch_message(id).await.expect("reported row");
        SnapshotContent::generate_from_message(db, reported)
            .await
            .expect("a snapshot or none, never an error")
            .map(|(snapshot, _)| snapshot_ids(&snapshot))
    }

    /// Design 7.5 "S4": a channel protected with its history snapshots the
    /// pre-boundary plaintext row (B itself included) as context and as the
    /// reported message, and still leaves out the stray above B
    ///
    /// Control: `<=` to `<` in `is_servable` -> the row at B is dropped.
    #[tokio::test]
    async fn boundary_snapshot_serves_pre_boundary_rows_and_drops_a_stray_above_b() {
        database_test!(|db| async move {
            seed_history(&db, wipe_none()).await;

            assert_eq!(
                snapshot_of(&db, REPORTED).await,
                Some((
                    REPORTED.to_string(),
                    vec![PRIOR_CIPHERTEXT.to_string(), PRIOR_STRAY.to_string()],
                    vec![LEADING_CIPHERTEXT.to_string()],
                )),
                "the row at B is kept, the stray above it dropped"
            );
            assert_eq!(
                snapshot_of(&db, PRIOR_STRAY).await,
                Some((
                    PRIOR_STRAY.to_string(),
                    vec![],
                    vec![
                        PRIOR_CIPHERTEXT.to_string(),
                        REPORTED.to_string(),
                        LEADING_CIPHERTEXT.to_string(),
                    ],
                )),
                "a reported pre-boundary row gets its server copy"
            );
            assert_eq!(snapshot_of(&db, LEADING_STRAY).await, None);
        });
    }

    /// S4-D21: from the moment the wipe is `Requested` the pre-boundary
    /// plaintext is unservable here too, as context and as the reported
    /// message
    ///
    /// Control: the wipe arm dropped from `is_servable` -> the row at B is
    /// snapshotted.
    #[tokio::test]
    async fn wipe_pending_snapshot_drops_pre_boundary_rows() {
        database_test!(|db| async move {
            seed_history(&db, wipe_requested()).await;
            let channel = db.fetch_channel(HISTORY_CHANNEL).await.expect("channel");
            assert!(crate::ProtectedReadView::of(&channel).wiped);

            assert_eq!(
                snapshot_of(&db, REPORTED).await,
                Some((
                    REPORTED.to_string(),
                    vec![PRIOR_CIPHERTEXT.to_string()],
                    vec![LEADING_CIPHERTEXT.to_string()],
                ))
            );
            assert_eq!(snapshot_of(&db, PRIOR_STRAY).await, None);
        });
    }

    /// S4-PA-15: both context queries carry the servable predicate, so a
    /// context list is full around unservable rows. Fifteen strays sit on
    /// each side of the reported message, between it and the next servable
    /// row: a post-filter alone would fetch fifteen strays and keep nothing.
    ///
    /// Control: the query filter dropped from either driver -> both lists
    /// are empty.
    #[tokio::test]
    async fn snapshot_context_is_full_around_strays() {
        database_test!(|db| async move {
            let id = |ms: u64| ulid::Ulid::from_parts(ms, 0).to_string();
            let (before_b, reported, after) = (id(1_000), id(2_000), id(4_000));
            db.insert_channel(&history_channel(FULL_CHANNEL, &before_b, wipe_none()))
                .await
                .expect("channel");
            insert_raw(&db, &plaintext_row(&before_b, FULL_CHANNEL)).await;
            for ms in (1_500..1_515).chain(3_000..3_015) {
                insert_raw(&db, &plaintext_row(&id(ms), FULL_CHANNEL)).await;
            }
            for row in [&reported, &after] {
                db.insert_message(&ciphertext_row(row, FULL_CHANNEL))
                    .await
                    .expect("ciphertext row");
            }

            assert_eq!(
                snapshot_of(&db, &reported).await,
                Some((reported.clone(), vec![before_b], vec![after]))
            );
        });
    }

    const ORPHAN_THREAD: &str = "01JB0SNAPTHREAD00000000000";
    const OPEN_THREAD: &str = "01JB0SNAPTHREAD00000000001";
    const PARENTLESS_THREAD: &str = "01JB0SNAPTHREAD00000000002";
    const THREAD_ROW: &str = "01JB0000000000000000000010";
    const OPEN_THREAD_ROW: &str = "01JB0000000000000000000011";

    fn thread(id: &str, parent: &str) -> Channel {
        serde_json::from_value(serde_json::json!({
            "channel_type": "Thread",
            "_id": id,
            "server": SERVER,
            "parent_channel": parent,
            "name": "thread",
            "creator": AUTHOR,
        }))
        .expect("thread")
    }
}
