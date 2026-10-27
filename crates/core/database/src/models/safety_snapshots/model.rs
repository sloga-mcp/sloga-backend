use revolt_models::v0::{MessageSort, ReportedMessageSnapshot};
use revolt_result::{ErrorType, Result};

use crate::{Database, Message, MessageFilter, MessageQuery, MessageTimePeriod, Server, User};

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

/// Drop every row a channel with `channel_protected` does not serve (R15
/// backstop), reporting each drop by ids only
fn retain_servable(messages: &mut Vec<Message>, channel_protected: bool) {
    messages.retain(|message| {
        let servable = message.is_servable(channel_protected);
        if !servable {
            report_dropped_row(message);
        }
        servable
    });
}

/// The protected flag a row of `channel_id` is judged by: the channel's own,
/// or for a thread its parent's (the permission target). `NotFound` when
/// either is missing; any other read error as is.
async fn message_channel_protected(db: &Database, channel_id: &str) -> Result<bool> {
    let channel = db.fetch_channel(channel_id).await?;
    Ok(channel.permission_target(db).await?.is_protected())
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
    /// In a protected channel every row without `encrypted` is dropped from
    /// both context lists (R15 backstop, design 7.5), and a reported message
    /// without `encrypted` gives `None`, so no snapshot embeds a stray
    /// plaintext row and none of its attachments are returned. Ciphertext
    /// rows are kept as stored. A thread's rows are judged by its parent. A
    /// channel (or thread parent) that no longer exists gives `None` too;
    /// any other failed channel read is an error, never a snapshot with
    /// unfiltered rows.
    pub async fn generate_from_message(
        db: &Database,
        message: Message,
    ) -> Result<Option<(SnapshotContent, Vec<String>)>> {
        // Collect prior context
        let mut prior_context = db
            .fetch_messages(MessageQuery {
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
            })
            .await?;

        // Collect leading context
        let mut leading_context = db
            .fetch_messages(MessageQuery {
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
            })
            .await?;

        // Read the flag after every row it judges (the reported message was
        // read by the caller): protect is one-way, so a row read while the
        // channel was already protected is judged as protected. A thread is
        // judged by its parent (W2 audit B1). A channel (or a thread's
        // parent) that no longer exists gives no server copy, like a stray
        // (W2 audit B3): the report is still filed without it.
        let channel_protected = match message_channel_protected(db, &message.channel).await {
            Ok(protected) => protected,
            Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        if !message.is_servable(channel_protected) {
            report_dropped_row(&message);
            return Ok(None);
        }

        retain_servable(&mut prior_context, channel_protected);
        retain_servable(&mut leading_context, channel_protected);

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

    /// The protected flag is read AFTER both context fetches and before any
    /// row is judged. Protect is one-way, so a flag read after the rows
    /// cannot call a row read under protection unprotected; read first, a
    /// protect landing in between would let a stray into the snapshot. No
    /// fault injection can land a protect between two awaits, hence source
    /// order. (W2 audit B1/B3: the read moved into
    /// `message_channel_protected`, which also reads a thread's parent, and
    /// its `NotFound` now gives `None`; the order pinned here is unchanged.)
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
            .match_indices(".fetch_messages(")
            .map(|(at, _)| at)
            .collect();
        assert_eq!(fetches.len(), 2, "two context fetches");
        let flag = body
            .find("let channel_protected = match message_channel_protected(db, &message.channel).await {")
            .expect("the flag read");
        assert_eq!(body.matches("message_channel_protected(").count(), 1);
        assert_eq!(body.matches(".fetch_channel(").count(), 0);
        let judged = [
            "if !message.is_servable(channel_protected) {",
            "retain_servable(&mut prior_context, channel_protected);",
            "retain_servable(&mut leading_context, channel_protected);",
        ]
        .map(|needle| body.find(needle).expect(needle));

        assert!(
            fetches.iter().all(|&fetch| fetch < flag),
            "the flag is read after both fetches"
        );
        assert!(
            judged.iter().all(|&at| flag < at),
            "every row is judged after the flag read"
        );
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
