//! History wipes of protected channels (design 7.5 "S4", S4-D22, S4-PA-9,
//! S4-PA-21; planner ruling R-WIPEJOB as amended).
//!
//! Every tick finds the channels whose `protected_history.wipe` is
//! `Requested` and deletes their plaintext rows at or below the boundary B
//! in batches of `history_wipe_batch_size()`. B is the STORED
//! `protected_history.boundary`, read from the channel row on every run,
//! never a client value (F3). A row carrying `encrypted` is never touched,
//! whatever its id, and nothing above B is deleted: the batch read and the
//! delete are both bounded by B.
//!
//! Per batch: the server's legal hold is read first (2.9), so a hold set
//! after the route's read still stops the wipe before its next batch; then
//! the files of the rows' `attachments` and `forwarded.attachments` are
//! marked deleted, their polls and softres sheets deleted (no events: the
//! rows are already unservable), their unread mentions removed and then the
//! rows deleted. Mentions go first, so a crash between the two leaves a row
//! the next run deletes, never a mention of a row that is gone (F3). When a
//! batch comes back empty the wipe becomes
//! `Done { at, count }` through a write that lands only over `requested`,
//! so it is written once; then the audit entry, the `last_message_id` reset
//! and `ChannelUpdate { protected_history }` on the server topic.
//!
//! Multi-replica safety: crond has no leader election, so each channel is
//! wiped under an atomic per-channel lease (`history_wipe_leases`, the
//! `scheduled_messages` claim precedent). A replica that finds another's
//! live lease skips the channel; an expired or released lease lets any
//! replica resume. The lease carries the running count. A batch is deleted
//! before it is counted, so after a crash `count` is a lower bound.
//!
//! A failing channel (a row that does not decode, a database error) stays
//! `Requested`: its lease is released, the error is logged every tick and
//! the channel sent to Sentry once per process, and the job goes on to the
//! next channel. That report is the only one on this path: a fixed message,
//! the channel id and where the error was raised, never the error's text,
//! since a decode error can quote the stored plaintext (the driver drops
//! it, F1). The job runs whatever `history_setting` says (7.1 "S4"): a
//! signed wipe never stays half done, and the legal hold is the stop.

use std::{
    collections::HashSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use iso8601_timestamp::Timestamp;
use log::{error, info, warn};
use revolt_database::{
    events::client::EventV1, AuditLogAction, AuditLogChange, AuditLogDraft, AuditLogEntry,
    AuditValue, Channel, Database, HistoryWipe, Message, Poll, ProtectedHistory, SoftResSheet,
    AMQP,
};
use revolt_models::v0;
use revolt_result::{create_error, ErrorType, Result};
use tokio::time::sleep;

/// Time between two passes
const TICK: Duration = Duration::from_secs(60);

/// Channel ids read per page of the scan
const PAGE: i64 = 100;

/// How long a lease lives unless a batch renews it: a replica that dies
/// mid-wipe holds its channel for at most this long
const LEASE_TTL_MS: i64 = 5 * 60 * 1000;

/// What one run did to one channel
#[derive(Debug)]
pub enum Outcome {
    /// Another replica holds a live lease; nothing was read or written
    Busy,
    /// The channel is gone or its wipe is not `Requested` (already `Done`,
    /// perhaps by another replica); the lease row is deleted, since no run
    /// will resume it
    NotRequested,
    /// A legal hold is set: the lease is released with its count and the
    /// wipe stays `Requested`
    Held,
    /// The lease lapsed between two batches and another replica took it;
    /// that replica carries on
    LeaseLost,
    /// The wipe is `Done` with `count` rows, after `batches` non-empty
    /// batches in this run; `update` is the event published on the server
    /// topic
    Done {
        count: u64,
        batches: u32,
        update: EventV1,
    },
}

/// What one batch did
#[derive(Debug, PartialEq, Eq)]
pub enum Batch {
    /// A legal hold is set; nothing was read or deleted
    Held,
    /// Nothing is left at or below B
    Empty,
    /// This many rows were deleted and counted on the lease
    Deleted(u64),
    /// The rows were deleted but the lease was no longer ours
    LeaseLost,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

/// Wipe every requested channel each tick, for as long as crond runs
pub async fn task(db: Database, _: AMQP) -> Result<()> {
    // One holder per task run; a restarted task waits out its old leases
    let holder = format!("crond-{}", ulid::Ulid::new());
    let mut reported = HashSet::new();

    loop {
        let batch = revolt_config::config()
            .await
            .features
            .protected_channels
            .history_wipe_batch_size();

        run_once(&db, &holder, i64::from(batch), &mut reported).await;

        sleep(TICK).await
    }
}

/// One pass over every channel whose wipe is `Requested`, in id order.
/// A failed channel is logged and the pass goes on; `reported` holds the
/// channels already sent to Sentry, so a stalled one reports once.
pub async fn run_once(
    db: &Database,
    holder: &str,
    batch: i64,
    reported: &mut HashSet<String>,
) -> Vec<(String, Result<Outcome>)> {
    let mut outcomes = Vec::new();
    let mut after: Option<String> = None;

    loop {
        let page = match db
            .fetch_channel_ids_with_requested_wipe(after.as_deref(), PAGE)
            .await
        {
            Ok(page) => page,
            Err(error) => {
                error!("HISTORY_WIPE_PAGE_FAILED after={after:?}: {error:?}");
                revolt_config::capture_error(&error);
                return outcomes;
            }
        };

        let Some(last) = page.last().cloned() else {
            return outcomes;
        };

        // A page that does not move past its cursor would be read forever
        if after.as_deref().is_some_and(|after| last.as_str() <= after) {
            error!("HISTORY_WIPE_PAGE_FAILED after={after:?}: the page did not advance");
            return outcomes;
        }

        for channel_id in page {
            let outcome = wipe_channel(db, &channel_id, holder, batch).await;

            match &outcome {
                Ok(Outcome::Done { count, .. }) => {
                    info!("history wipe of {channel_id} done: {count} rows");
                    reported.remove(&channel_id);
                }
                Ok(Outcome::NotRequested) => {
                    reported.remove(&channel_id);
                }
                Ok(Outcome::Held) => info!("history wipe of {channel_id} paused by a legal hold"),
                Ok(Outcome::LeaseLost) => {
                    warn!("history wipe of {channel_id} lost its lease; another replica carries on")
                }
                Ok(Outcome::Busy) => {}
                Err(error) => {
                    error!("HISTORY_WIPE_FAILED channel={channel_id}, stays requested: {error:?}");
                    if reported.insert(channel_id.clone()) {
                        revolt_config::capture_message(
                            &failure_report(&channel_id, error),
                            revolt_config::Level::Error,
                        );
                    }
                }
            }

            outcomes.push((channel_id, outcome));
        }

        after = Some(last);
    }
}

/// The Sentry message for a channel whose wipe failed: a fixed text, the
/// channel id and the source location the error was raised at. Never the
/// error itself, whose text can quote a stored row (F1).
fn failure_report(channel_id: &str, error: &revolt_result::Error) -> String {
    format!(
        "history wipe of channel {channel_id} failed and stays requested (raised at {})",
        error.location
    )
}

/// Run one channel's wipe under its lease, to `Done` or to the first stop
pub async fn wipe_channel(
    db: &Database,
    channel_id: &str,
    holder: &str,
    batch: i64,
) -> Result<Outcome> {
    let Some(count) = db
        .claim_history_wipe_lease(channel_id, holder, now_ms(), LEASE_TTL_MS)
        .await?
    else {
        return Ok(Outcome::Busy);
    };

    let outcome = wipe_claimed(db, channel_id, holder, batch, count).await;

    // A hold and a failure hand the lease back with its count, so the next
    // run on any replica resumes at once. A lost lease is not ours to
    // release, and the other outcomes have deleted the row.
    if matches!(outcome, Ok(Outcome::Held) | Err(_)) {
        if let Err(error) = db.release_history_wipe_lease(channel_id, holder).await {
            warn!(
                "HISTORY_WIPE_RELEASE_FAILED channel={channel_id}, it lapses within \
                 {LEASE_TTL_MS} ms: {error:?}"
            );
        }
    }

    outcome
}

/// The wipe of a channel whose lease is held, starting from `count`
async fn wipe_claimed(
    db: &Database,
    channel_id: &str,
    holder: &str,
    batch: i64,
    mut count: u64,
) -> Result<Outcome> {
    let channel = match db.fetch_channel(channel_id).await {
        Ok(channel) => Some(channel),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
        Err(error) => return Err(error),
    };

    let Some((server, boundary)) = channel.as_ref().and_then(requested_wipe) else {
        db.delete_history_wipe_lease(channel_id).await?;
        return Ok(Outcome::NotRequested);
    };

    let mut batches = 0u32;
    loop {
        match wipe_batch(db, channel_id, &server, &boundary, batch, holder).await? {
            Batch::Deleted(deleted) => {
                count = count.saturating_add(deleted);
                batches += 1;
            }
            Batch::Empty => break,
            Batch::Held => return Ok(Outcome::Held),
            Batch::LeaseLost => return Ok(Outcome::LeaseLost),
        }
    }

    complete(db, channel_id, &server, &boundary, count, batches).await
}

/// The server and the STORED boundary B of a protected text channel whose
/// wipe is `Requested`; `None` for anything else
fn requested_wipe(channel: &Channel) -> Option<(String, String)> {
    match channel {
        Channel::TextChannel {
            server,
            protected: true,
            protected_history: Some(history),
            ..
        } if matches!(history.wipe, HistoryWipe::Requested { .. })
            && !history.boundary.is_empty() =>
        {
            Some((server.clone(), history.boundary.clone()))
        }
        _ => None,
    }
}

/// One batch of `channel_id`'s wipe at or below `boundary`, with the lease
/// held by `holder`
pub async fn wipe_batch(
    db: &Database,
    channel_id: &str,
    server: &str,
    boundary: &str,
    batch: i64,
    holder: &str,
) -> Result<Batch> {
    // 2.9: the hold is read before EVERY batch and never lets a wipe go on
    if db.fetch_server_legal_hold(server).await?.is_some() {
        return Ok(Batch::Held);
    }

    let rows = db
        .fetch_history_wipe_batch(channel_id, boundary, batch)
        .await?;
    if rows.is_empty() {
        return Ok(Batch::Empty);
    }

    wipe_rows(db, channel_id, boundary, holder, &rows).await
}

/// Everything a batch does once its non-empty `rows` are read
async fn wipe_rows(
    db: &Database,
    channel_id: &str,
    boundary: &str,
    holder: &str,
    rows: &[Message],
) -> Result<Batch> {
    let ids: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();

    let files = attachment_ids(rows);
    if !files.is_empty() {
        db.mark_attachments_as_deleted(&files).await?;
    }
    Poll::delete_for_messages(db, &ids).await?;
    SoftResSheet::delete_for_messages(db, &ids).await?;

    // Per batch and BEFORE the delete (F3): a crash between the two leaves
    // rows the next run deletes, never a mention of a row that is gone
    db.remove_mentions_of_messages(channel_id, &ids).await?;

    let deleted = db
        .delete_messages_by_ids(channel_id, boundary, &ids)
        .await?;
    if deleted == 0 {
        // The read and the delete share one filter, so a batch that deletes
        // nothing would be read again forever
        error!(
            "HISTORY_WIPE_STUCK channel={channel_id}: {} rows read, none deleted",
            ids.len()
        );
        return Err(create_error!(InternalError));
    }

    if !db
        .advance_history_wipe_lease(channel_id, holder, deleted, now_ms(), LEASE_TTL_MS)
        .await?
    {
        return Ok(Batch::LeaseLost);
    }

    Ok(Batch::Deleted(deleted))
}

/// Ids of the files a batch's rows hold, their own and their forwarded
/// copies
fn attachment_ids(rows: &[Message]) -> Vec<String> {
    rows.iter()
        .flat_map(|row| {
            let own = row.attachments.iter().flatten();
            let forwarded = row
                .forwarded
                .iter()
                .flat_map(|snapshot| snapshot.attachments.iter());
            own.chain(forwarded).map(|file| file.id.clone())
        })
        .collect()
}

/// Mark the wipe `Done` once nothing is left, then audit, reset
/// `last_message_id`, announce and drop the lease
async fn complete(
    db: &Database,
    channel_id: &str,
    server: &str,
    boundary: &str,
    count: u64,
    batches: u32,
) -> Result<Outcome> {
    // Whole milliseconds, as MongoDB stores it, so the event carries the
    // stored value
    let at = Timestamp::UNIX_EPOCH
        .checked_add(iso8601_timestamp::Duration::milliseconds(now_ms()))
        .unwrap_or_else(Timestamp::now_utc);

    if !db.complete_history_wipe(channel_id, at, count).await? {
        // Another replica wrote `Done` first, or the channel went
        db.delete_history_wipe_lease(channel_id).await?;
        return Ok(Outcome::NotRequested);
    }

    // `Done` is written and no later run comes back to this channel, so
    // the steps below are best effort: each failure is reported and the
    // rest still run
    AuditLogEntry::record(
        db,
        AuditLogDraft {
            server: server.to_string(),
            action: AuditLogAction::ChannelHistoryWipe,
            channel: Some(channel_id.to_string()),
            changes: vec![AuditLogChange {
                key: "count".to_string(),
                old: None,
                new: Some(AuditValue::Int(i64::try_from(count).unwrap_or(i64::MAX))),
            }],
            ..Default::default()
        },
    )
    .await;

    let reset = match db.fetch_newest_message_id(channel_id).await {
        Ok(newest) => db
            .reset_last_message_id_after_wipe(channel_id, boundary, newest)
            .await
            .map(|_| ()),
        Err(error) => Err(error),
    };
    if let Err(error) = reset {
        error!("HISTORY_WIPE_LAST_MESSAGE_RESET_FAILED channel={channel_id}: {error:?}");
        revolt_config::capture_error(&error);
    }

    // 7.5 "S4": on the SERVER topic, as the route and protect (#149)
    let update = EventV1::ChannelUpdate {
        id: channel_id.to_string(),
        data: v0::PartialChannel {
            protected_history: Some(Box::new(
                ProtectedHistory {
                    boundary: boundary.to_string(),
                    wipe: HistoryWipe::Done { at, count },
                }
                .into(),
            )),
            ..Default::default()
        },
        clear: vec![],
    };
    update.clone().p(server.to_string()).await;

    if let Err(error) = db.delete_history_wipe_lease(channel_id).await {
        error!("HISTORY_WIPE_LEASE_DELETE_FAILED channel={channel_id}: {error:?}");
        revolt_config::capture_error(&error);
    }

    Ok(Outcome::Done {
        count,
        batches,
        update,
    })
}

#[cfg(test)]
mod tests {
    //! Database tests run on the driver `TEST_DB` names, REFERENCE and
    //! MONGODB (never without it: `DatabaseInfo::Test` panics rather than
    //! reach the configured database).

    use std::{
        collections::HashMap,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
    };

    use revolt_database::{
        mongodb::bson::{doc, Document},
        test_teardown::TestDatabaseGuard,
        DatabaseInfo, EncryptedPayload, File, FileUsedFor, FileUsedForType, ForwardedSnapshot,
        Metadata, PollVote, ServerLegalHold, SoftResReserveRow,
    };

    use super::*;

    const SERVER: &str = "01HZXW1PESERVER00000000000";
    const USER: &str = "01HZXW1PEUSER0000000000000";
    const CHANNEL_A: &str = "01HZXW1PECHANNE1A000000000";
    const CHANNEL_B: &str = "01HZXW1PECHANNE1B000000000";
    const CHANNEL_C: &str = "01HZXW1PECHANNE1C000000000";
    const CHANNEL_D: &str = "01HZXW1PECHANNE1D000000000";

    /// A fresh test database on the driver `TEST_DB` names, in the harness
    /// name shape the guard drops when the test ends, panics included
    async fn test_db() -> (Database, TestDatabaseGuard) {
        let suffix = 1_000_000 + (ulid::Ulid::new().random() % 9_000_000);
        let db = DatabaseInfo::Test(format!("revolt_test_{suffix}"))
            .connect()
            .await
            .expect("test database");
        let guard = TestDatabaseGuard::arm(&db).await;
        (db, guard)
    }

    /// A ULID whose time part is `t`, so ids from a larger `t` sort later
    fn id(t: u64) -> String {
        ulid::Ulid::from_parts(t, 0).to_string()
    }

    /// Whole milliseconds: MongoDB stores a `Timestamp` in milliseconds
    fn at_ms(ms: i64) -> Timestamp {
        Timestamp::UNIX_EPOCH
            .checked_add(iso8601_timestamp::Duration::milliseconds(ms))
            .unwrap()
    }

    fn requested() -> HistoryWipe {
        HistoryWipe::Requested {
            at: at_ms(1_790_812_800_000),
            by: USER.to_string(),
        }
    }

    fn hold() -> ServerLegalHold {
        ServerLegalHold {
            id: SERVER.to_string(),
            set_at: at_ms(1_790_812_900_000),
            set_by: "01HZXW1PESTAFF000000000000".to_string(),
            note: None,
        }
    }

    fn text_channel(
        channel_id: &str,
        last_message_id: Option<&str>,
        history: Option<ProtectedHistory>,
    ) -> Channel {
        Channel::TextChannel {
            id: channel_id.to_string(),
            server: SERVER.to_string(),
            name: "history".to_string(),
            description: None,
            icon: None,
            last_message_id: last_message_id.map(str::to_string),
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected: true,
            protected_history: history.map(Box::new),
        }
    }

    fn file(file_id: &str, message_id: &str) -> File {
        File {
            id: file_id.to_string(),
            tag: "attachments".to_string(),
            filename: "photo.png".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: Some(FileUsedFor {
                object_type: FileUsedForType::Message,
                id: message_id.to_string(),
            }),
            deleted: None,
            reported: None,
            metadata: Metadata::File,
            content_type: "image/png".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    fn plaintext(channel_id: &str, message_id: &str) -> Message {
        Message {
            id: message_id.to_string(),
            channel: channel_id.to_string(),
            author: USER.to_string(),
            content: Some("before protect".to_string()),
            ..Default::default()
        }
    }

    fn encrypted(channel_id: &str, message_id: &str) -> Message {
        Message {
            id: message_id.to_string(),
            channel: channel_id.to_string(),
            author: USER.to_string(),
            nonce: Some(message_id.to_string()),
            encrypted: Some(EncryptedPayload {
                v: EncryptedPayload::VERSION,
                group_id: "ab".repeat(32),
                epoch: 1,
                sender_device_id: "0a".repeat(16),
                nonce: "AAAA".to_string(),
                ciphertext: "AAAA".to_string(),
                sig: "AAAA".to_string(),
                franking: None,
            }),
            ..Default::default()
        }
    }

    fn poll(poll_id: &str, message_id: &str, channel_id: &str) -> Poll {
        Poll {
            id: poll_id.to_string(),
            message: message_id.to_string(),
            channel: channel_id.to_string(),
            server: Some(SERVER.to_string()),
            author: USER.to_string(),
            question: "Best crab?".to_string(),
            answers: vec![
                v0::PollAnswer {
                    id: 0,
                    text: "Ferris".to_string(),
                    emoji: None,
                },
                v0::PollAnswer {
                    id: 1,
                    text: "Sebastian".to_string(),
                    emoji: None,
                },
            ],
            allow_multiselect: false,
            expires_at: 4_000_000_000_000,
            closed: false,
            counts: HashMap::new(),
            total_votes: 0,
        }
    }

    fn sheet(sheet_id: &str, message_id: &str, channel_id: &str) -> SoftResSheet {
        SoftResSheet {
            id: sheet_id.to_string(),
            message: message_id.to_string(),
            channel: channel_id.to_string(),
            server: Some(SERVER.to_string()),
            event: None,
            creator: USER.to_string(),
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

    /// Store a message straight through the driver: the plaintext rows
    /// predate protect, and `insert_message` refuses plaintext on a
    /// protected channel
    async fn seed(db: &Database, message: Message) {
        match db {
            Database::Reference(reference) => {
                reference
                    .messages
                    .lock()
                    .await
                    .insert(message.id.clone(), message);
            }
            Database::MongoDb(mongo) => {
                mongo
                    .col::<Message>("messages")
                    .insert_one(&message)
                    .await
                    .expect("message");
            }
        }
    }

    /// One protected channel and its rows, oldest first
    struct World {
        /// The plaintext rows at or below B, oldest first; the last is B
        wiped: Vec<String>,
        /// A ciphertext row below B
        encrypted_below: String,
        /// A plaintext stray above B
        stray_above: String,
        /// A ciphertext row above B, the newest row
        encrypted_above: String,
        /// On a wiped row, and on the stray
        poll_wiped: String,
        poll_kept: String,
        /// On a wiped row, and on the newest ciphertext row
        sheet_wiped: String,
        sheet_kept: String,
        /// A wiped row's own file, a wiped row's forwarded copy, the stray's
        file_wiped: String,
        file_forwarded: String,
        file_kept: String,
    }

    impl World {
        fn boundary(&self) -> &str {
            self.wiped.last().expect("rows")
        }

        fn survivors(&self) -> Vec<String> {
            vec![
                self.encrypted_below.clone(),
                self.stray_above.clone(),
                self.encrypted_above.clone(),
            ]
        }

        fn all(&self) -> Vec<String> {
            let mut all = self.wiped.clone();
            all.extend(self.survivors());
            all
        }
    }

    /// `channel_id` with five plaintext rows at or below B (the fifth is B),
    /// a ciphertext row among them, a plaintext stray and a ciphertext row
    /// above B; polls, sheets and files on both sides of B, and one
    /// user's unread mentions of a wiped row and both rows above B. The
    /// stored `last_message_id` is B, so the reset after the wipe shows.
    /// `protected_history` carries `wipe` when it is `Some`. Ids are
    /// `base + n`, so worlds in one database never collide.
    async fn world(db: &Database, channel_id: &str, base: u64, wipe: Option<HistoryWipe>) -> World {
        let row = |n: u64| id(base + n);
        let (p1, p2, e3, p4, p5, p6) = (row(1), row(2), row(3), row(4), row(5), row(6));
        let (s20, e21) = (row(20), row(21));
        let name = |what: &str| format!("{channel_id}-{what}");

        let world = World {
            wiped: vec![p1.clone(), p2.clone(), p4.clone(), p5.clone(), p6.clone()],
            encrypted_below: e3.clone(),
            stray_above: s20.clone(),
            encrypted_above: e21.clone(),
            poll_wiped: name("POLL1"),
            poll_kept: name("POLL2"),
            sheet_wiped: name("SHEET1"),
            sheet_kept: name("SHEET2"),
            file_wiped: name("FILE1"),
            file_forwarded: name("FILE2"),
            file_kept: name("FILE3"),
        };

        db.insert_channel(&text_channel(
            channel_id,
            Some(&p6),
            wipe.map(|wipe| ProtectedHistory {
                boundary: p6.clone(),
                wipe,
            }),
        ))
        .await
        .unwrap();

        for (file_id, message_id) in [
            (&world.file_wiped, &p1),
            (&world.file_forwarded, &p4),
            (&world.file_kept, &s20),
        ] {
            db.insert_attachment(&file(file_id, message_id))
                .await
                .unwrap();
        }

        let mut first = plaintext(channel_id, &p1);
        first.attachments = Some(vec![file(&world.file_wiped, &p1)]);
        let mut forward = plaintext(channel_id, &p4);
        forward.forwarded = Some(ForwardedSnapshot {
            message_id: "01HZXW1PE0R1G1NA1000000000".to_string(),
            channel_id: "01HZXW1PE0THERCHANNE100000".to_string(),
            server_id: None,
            author_id: None,
            content: Some("forwarded".to_string()),
            attachments: vec![file(&world.file_forwarded, &p4)],
            original_sent_at: 0,
        });
        let mut stray = plaintext(channel_id, &s20);
        stray.attachments = Some(vec![file(&world.file_kept, &s20)]);

        for message in [
            first,
            plaintext(channel_id, &p2),
            encrypted(channel_id, &e3),
            forward,
            plaintext(channel_id, &p5),
            plaintext(channel_id, &p6),
            stray,
            encrypted(channel_id, &e21),
        ] {
            seed(db, message).await;
        }

        let poll_wiped = poll(&world.poll_wiped, &p2, channel_id);
        db.insert_poll(&poll_wiped).await.unwrap();
        db.insert_poll(&poll(&world.poll_kept, &s20, channel_id))
            .await
            .unwrap();
        db.upsert_poll_vote(&PollVote {
            id: Poll::vote_key(&poll_wiped.id, USER),
            poll: poll_wiped.id.clone(),
            user: USER.to_string(),
            channel: channel_id.to_string(),
            answer_ids: vec![0],
        })
        .await
        .unwrap();

        let sheet_wiped = sheet(&world.sheet_wiped, &p4, channel_id);
        db.insert_sheet(&sheet_wiped).await.unwrap();
        db.insert_sheet(&sheet(&world.sheet_kept, &e21, channel_id))
            .await
            .unwrap();
        db.upsert_reserve(&SoftResReserveRow {
            id: SoftResSheet::reserve_key(&sheet_wiped.id, USER),
            sheet: sheet_wiped.id.clone(),
            user: USER.to_string(),
            channel: channel_id.to_string(),
            character_name: "Leeroy".to_string(),
            class: v0::WowClass::Paladin,
            items: vec![17204],
            note: None,
            plus_ones: 0,
            edited_at: 1_000_001,
        })
        .await
        .unwrap();

        db.add_mention_to_unread(channel_id, USER, &[p2, s20, e21])
            .await
            .unwrap();

        world
    }

    async fn present(db: &Database, ids: &[String]) -> Vec<String> {
        let mut present = Vec::new();
        for message_id in ids {
            if db.fetch_message(message_id).await.is_ok() {
                present.push(message_id.clone());
            }
        }
        present
    }

    async fn stored_wipe(db: &Database, channel_id: &str) -> Option<HistoryWipe> {
        match db.fetch_channel(channel_id).await.unwrap() {
            Channel::TextChannel {
                protected_history, ..
            } => protected_history.map(|history| history.wipe),
            other => panic!("expected a text channel, got {other:?}"),
        }
    }

    async fn last_message_id(db: &Database, channel_id: &str) -> Option<String> {
        match db.fetch_channel(channel_id).await.unwrap() {
            Channel::TextChannel {
                last_message_id, ..
            } => last_message_id,
            other => panic!("expected a text channel, got {other:?}"),
        }
    }

    async fn wipe_entries(db: &Database) -> Vec<AuditLogEntry> {
        db.fetch_audit_log(
            SERVER,
            None,
            100,
            Some(AuditLogAction::ChannelHistoryWipe),
            None,
        )
        .await
        .unwrap()
    }

    async fn mentions(db: &Database, channel_id: &str) -> Vec<String> {
        db.fetch_unread(USER, channel_id)
            .await
            .unwrap()
            .and_then(|unread| unread.mentions)
            .unwrap_or_default()
    }

    async fn deleted_files(db: &Database) -> Vec<String> {
        let mut ids: Vec<String> = db
            .fetch_deleted_attachments()
            .await
            .unwrap()
            .into_iter()
            .map(|file| file.id)
            .collect();
        ids.sort();
        ids
    }

    fn done(outcome: Result<Outcome>) -> (u64, u32, EventV1) {
        match outcome {
            Ok(Outcome::Done {
                count,
                batches,
                update,
            }) => (count, batches, update),
            other => panic!("expected the wipe to be done, got {other:?}"),
        }
    }

    /// 7.5 "S4": five rows at or below B in batches of two take three
    /// batches; `Done` is written once with count 5, one audit entry
    /// carries it, `last_message_id` moves to the newest remaining row, the
    /// `ChannelUpdate` carries `Done` and the lease row is gone. A second
    /// run changes nothing.
    ///
    /// Controls: B replaced by a value above the stored boundary; `Done`
    /// written before the batch is empty.
    #[tokio::test]
    async fn a_requested_wipe_runs_in_batches_and_is_done_once() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;

        let (count, batches, update) = done(wipe_channel(&db, CHANNEL_A, "replica-a", 2).await);
        assert_eq!((count, batches), (5, 3));

        assert_eq!(present(&db, &world.all()).await, world.survivors());
        assert!(
            matches!(
                stored_wipe(&db, CHANNEL_A).await,
                Some(HistoryWipe::Done { count: 5, .. })
            ),
            "{:?}",
            stored_wipe(&db, CHANNEL_A).await
        );
        assert_eq!(
            last_message_id(&db, CHANNEL_A).await,
            Some(world.encrypted_above.clone())
        );

        let entries = wipe_entries(&db).await;
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].actor, None);
        assert_eq!(entries[0].channel.as_deref(), Some(CHANNEL_A));
        assert_eq!(
            entries[0].changes,
            vec![AuditLogChange {
                key: "count".to_string(),
                old: None,
                new: Some(AuditValue::Int(5)),
            }]
        );

        match &update {
            EventV1::ChannelUpdate { id, data, clear } => {
                assert_eq!(id, CHANNEL_A);
                assert!(clear.is_empty());
                let history = data.protected_history.as_ref().expect("protected_history");
                assert_eq!(history.boundary, world.boundary());
                assert!(
                    matches!(history.wipe, v0::HistoryWipe::Done { count: 5, .. }),
                    "{:?}",
                    history.wipe
                );
            }
            other => panic!("expected a ChannelUpdate, got {other:?}"),
        }

        // The lease row is gone: a new claim starts a fresh row at 0
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-b", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );
        db.delete_history_wipe_lease(CHANNEL_A).await.unwrap();

        // Done once: a second run finds nothing requested
        assert!(matches!(
            wipe_channel(&db, CHANNEL_A, "replica-a", 2).await,
            Ok(Outcome::NotRequested)
        ));
        assert_eq!(wipe_entries(&db).await.len(), 1);
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Done { count: 5, .. })
        ));
        assert_eq!(present(&db, &world.all()).await, world.survivors());
    }

    /// 7.5 "S4" step (4): the polls (with their ballots) and the sheets
    /// (with their reserves) of wiped rows are deleted, and the files of
    /// their attachments and forwarded copies marked deleted; those of the
    /// rows that survive are kept.
    ///
    /// Control: the poll delete dropped.
    #[tokio::test]
    async fn polls_sheets_and_files_of_wiped_rows_go_with_them() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;

        done(wipe_channel(&db, CHANNEL_A, "replica-a", 2).await);

        assert!(db.fetch_poll(&world.poll_wiped).await.is_err());
        assert!(db
            .fetch_poll_votes(&world.poll_wiped)
            .await
            .unwrap()
            .is_empty());
        assert!(db.fetch_poll(&world.poll_kept).await.is_ok());

        assert!(db.fetch_sheet(&world.sheet_wiped).await.is_err());
        assert!(db
            .fetch_reserves_for_sheet(&world.sheet_wiped)
            .await
            .unwrap()
            .is_empty());
        assert!(db.fetch_sheet(&world.sheet_kept).await.is_ok());

        let mut want = vec![world.file_wiped.clone(), world.file_forwarded.clone()];
        want.sort();
        assert_eq!(deleted_files(&db).await, want);
    }

    /// 7.5 "S4" step (5), amended to run per batch: the unread mentions of
    /// wiped rows are removed, and the mentions of the rows above B stay.
    ///
    /// Control: the per-batch mention removal dropped.
    #[tokio::test]
    async fn mentions_of_wiped_rows_are_removed_and_survivors_stay() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        assert_eq!(mentions(&db, CHANNEL_A).await.len(), 3);

        done(wipe_channel(&db, CHANNEL_A, "replica-a", 2).await);

        assert_eq!(
            mentions(&db, CHANNEL_A).await,
            vec![world.stray_above.clone(), world.encrypted_above.clone()]
        );
    }

    /// 2.9: a legal hold set after a first batch stops the next run before
    /// it deletes anything, and the wipe stays `Requested`; once the hold
    /// is cleared a later run resumes the count the lease kept.
    ///
    /// Control: the per-batch hold read dropped.
    #[tokio::test]
    async fn a_legal_hold_stops_the_wipe_and_a_later_run_resumes_the_count() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;

        // A first run deletes one batch, then stops
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-a", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            wipe_batch(&db, CHANNEL_A, SERVER, world.boundary(), 2, "replica-a")
                .await
                .unwrap(),
            Batch::Deleted(2)
        );
        db.release_history_wipe_lease(CHANNEL_A, "replica-a")
            .await
            .unwrap();
        let left = present(&db, &world.all()).await;
        assert_eq!(left.len(), 6);

        db.set_server_legal_hold(&hold()).await.unwrap();
        assert!(matches!(
            wipe_channel(&db, CHANNEL_A, "replica-b", 2).await,
            Ok(Outcome::Held)
        ));
        assert_eq!(present(&db, &world.all()).await, left);
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Requested { .. })
        ));
        assert!(wipe_entries(&db).await.is_empty());

        db.clear_server_legal_hold(SERVER).await.unwrap();
        let (count, batches, _) = done(wipe_channel(&db, CHANNEL_A, "replica-b", 2).await);
        assert_eq!((count, batches), (5, 2), "2 kept on the lease + 3 now");
        assert_eq!(present(&db, &world.all()).await, world.survivors());
    }

    /// A replica that finds another's live lease skips the channel and
    /// reads or deletes nothing.
    ///
    /// Control: the claim's answer ignored (the claim always succeeds).
    #[tokio::test]
    async fn a_second_replica_holding_the_lease_is_skipped() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;

        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-a", now_ms(), 10 * 60 * 1000)
                .await
                .unwrap(),
            Some(0)
        );

        assert!(matches!(
            wipe_channel(&db, CHANNEL_A, "replica-b", 2).await,
            Ok(Outcome::Busy)
        ));
        assert_eq!(present(&db, &world.all()).await, world.all());
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Requested { .. })
        ));
        assert_eq!(mentions(&db, CHANNEL_A).await.len(), 3);
    }

    /// A pass wipes only the channel whose wipe is `Requested`: a channel
    /// whose wipe is `None` or `Done`, and one with no `protected_history`,
    /// keep every row and their stored state; run directly on one of them
    /// the job does nothing either.
    #[tokio::test]
    async fn channels_not_requested_are_untouched() {
        let (db, _guard) = test_db().await;
        let a = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        let b = world(&db, CHANNEL_B, 2_000, Some(HistoryWipe::None)).await;
        let earlier = HistoryWipe::Done {
            at: at_ms(1_790_812_850_000),
            count: 9,
        };
        let c = world(&db, CHANNEL_C, 3_000, Some(earlier.clone())).await;
        let d = world(&db, CHANNEL_D, 4_000, None).await;

        let outcomes = run_once(&db, "replica-a", 2, &mut HashSet::new()).await;
        assert_eq!(outcomes.len(), 1, "{outcomes:?}");
        assert_eq!(outcomes[0].0, CHANNEL_A);
        assert!(matches!(outcomes[0].1, Ok(Outcome::Done { count: 5, .. })));
        assert_eq!(present(&db, &a.all()).await, a.survivors());

        assert!(matches!(
            wipe_channel(&db, CHANNEL_B, "replica-a", 2).await,
            Ok(Outcome::NotRequested)
        ));

        for (channel_id, world, wipe) in [
            (CHANNEL_B, &b, Some(HistoryWipe::None)),
            (CHANNEL_C, &c, Some(earlier)),
            (CHANNEL_D, &d, None),
        ] {
            assert_eq!(
                present(&db, &world.all()).await,
                world.all(),
                "{channel_id}"
            );
            assert_eq!(stored_wipe(&db, channel_id).await, wipe, "{channel_id}");
            assert_eq!(mentions(&db, channel_id).await.len(), 3, "{channel_id}");
            assert!(
                db.fetch_poll(&world.poll_wiped).await.is_ok(),
                "{channel_id}"
            );
        }
        assert_eq!(wipe_entries(&db).await.len(), 1);
    }

    /// A row that does not decode fails its channel's batch closed: the
    /// channel stays `Requested` with every row, its lease is released, it
    /// is reported once, and the pass still wipes the next channel.
    /// MongoDB only: the Reference driver cannot hold an undecodable row.
    #[tokio::test]
    async fn a_poisoned_row_stalls_its_channel_and_the_job_moves_on() {
        let (db, _guard) = test_db().await;
        let Database::MongoDb(mongo) = &db else {
            eprintln!(
                "NOTE: a_poisoned_row_stalls_its_channel_and_the_job_moves_on runs on MONGODB \
                 only; skipped on REFERENCE"
            );
            return;
        };
        let a = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        let b = world(&db, CHANNEL_B, 2_000, Some(requested())).await;
        mongo
            .col::<Document>("messages")
            .insert_one(doc! {
                "_id": id(1_000),
                "channel": CHANNEL_A,
                "author": 5_i32,
            })
            .await
            .unwrap();

        let mut reported = HashSet::new();
        let outcomes = run_once(&db, "replica-a", 2, &mut reported).await;
        assert_eq!(outcomes.len(), 2, "{outcomes:?}");
        assert_eq!(outcomes[0].0, CHANNEL_A);
        assert!(outcomes[0].1.is_err(), "{:?}", outcomes[0].1);
        assert_eq!(outcomes[1].0, CHANNEL_B);
        assert!(matches!(outcomes[1].1, Ok(Outcome::Done { count: 5, .. })));
        assert_eq!(reported, HashSet::from([CHANNEL_A.to_string()]));

        assert_eq!(present(&db, &a.all()).await, a.all());
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Requested { .. })
        ));
        assert_eq!(present(&db, &b.all()).await, b.survivors());

        // Released: another replica can claim it at once
        assert!(db
            .claim_history_wipe_lease(CHANNEL_A, "replica-z", now_ms(), LEASE_TTL_MS)
            .await
            .unwrap()
            .is_some());
    }

    /// Plaintext a poisoned row holds where a list belongs; a decode error
    /// quotes it
    const SENTINEL: &str = "SENTINEL-PLAINTEXT the crab recipe";

    /// A local Sentry endpoint that keeps the body (the envelope) of every
    /// request the SDK sends it
    struct SentrySink {
        dsn: String,
        bodies: Arc<Mutex<Vec<String>>>,
    }

    impl SentrySink {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind the Sentry sink");
            let port = listener.local_addr().expect("sink address").port();
            let bodies = Arc::new(Mutex::new(Vec::new()));
            let kept = bodies.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming().flatten() {
                    let kept = kept.clone();
                    std::thread::spawn(move || serve_sentry(stream, &kept));
                }
            });
            SentrySink {
                dsn: format!("http://public@127.0.0.1:{port}/1"),
                bodies,
            }
        }

        fn bodies(&self) -> Vec<String> {
            self.bodies.lock().unwrap().clone()
        }
    }

    /// Answer every request on one connection with a 200, keeping its body
    fn serve_sentry(mut stream: TcpStream, bodies: &Mutex<Vec<String>>) {
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            // One request: the head, then `content-length` bytes of body
            let head_end = loop {
                if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buffer.len() < head_end + length {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                }
            }
            let body = String::from_utf8_lossy(&buffer[head_end..head_end + length]).into_owned();
            bodies.lock().unwrap().push(body);
            buffer.drain(..head_end + length);
            if stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .is_err()
            {
                return;
            }
        }
    }

    /// F1: a row that does not decode, whose bad field holds plaintext,
    /// stalls its channel over two ticks with ONE Sentry event in the whole
    /// process: the fixed message and the channel id, never the plaintext.
    /// The channel stays `Requested` with every row. Events are read off a
    /// local Sentry endpoint, so a report from the driver counts too.
    /// MongoDB only: the Reference driver cannot hold an undecodable row.
    ///
    /// Controls: the decode error reported from the driver (the old code); a
    /// fixed report from the driver on every call; the `reported` dedupe
    /// dropped.
    #[tokio::test]
    async fn a_poisoned_row_is_reported_once_and_never_by_its_text() {
        let (db, _guard) = test_db().await;
        let Database::MongoDb(mongo) = &db else {
            eprintln!(
                "NOTE: a_poisoned_row_is_reported_once_and_never_by_its_text runs on MONGODB \
                 only; skipped on REFERENCE"
            );
            return;
        };
        let sink = SentrySink::start();
        let sentry = revolt_config::setup_logging("revolt-crond@test", sink.dsn.clone())
            .await
            .expect("a Sentry client");

        let a = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        // Older than every row of the world, so the first batch reads it
        let poisoned = id(1_000);
        mongo
            .col::<Document>("messages")
            .insert_one(doc! {
                "_id": poisoned.as_str(),
                "channel": CHANNEL_A,
                "author": USER,
                "attachments": SENTINEL,
            })
            .await
            .unwrap();
        // Proof of the fixture: the decode error quotes the plaintext
        let decode = mongo
            .col::<Message>("messages")
            .find_one(doc! { "_id": poisoned.as_str() })
            .await
            .unwrap_err();
        assert!(format!("{decode:?}").contains(SENTINEL), "{decode:?}");

        let mut reported = HashSet::new();
        for tick in 1..=2 {
            let outcomes = run_once(&db, "replica-a", 2, &mut reported).await;
            assert_eq!(outcomes.len(), 1, "tick {tick}: {outcomes:?}");
            assert!(outcomes[0].1.is_err(), "tick {tick}: {:?}", outcomes[0].1);
        }

        // Waits until every queued event has been answered by the sink. The
        // answer is not read: sentry 0.31's transport thread inverts it
        // (`recv_timeout(..).is_err()`)
        let _ = sentry.flush(Some(Duration::from_secs(10)));
        let bodies = sink.bodies();
        assert!(
            bodies.iter().all(|body| !body.contains("SENTINEL")),
            "a Sentry event quotes the row: {bodies:#?}"
        );
        assert_eq!(
            bodies.len(),
            1,
            "one Sentry event in two ticks: {bodies:#?}"
        );
        assert!(
            bodies[0].contains(&format!(
                "history wipe of channel {CHANNEL_A} failed and stays requested"
            )),
            "{}",
            bodies[0]
        );

        // Failed closed: still requested, every row kept, the poisoned one too
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Requested { .. })
        ));
        assert_eq!(present(&db, &a.all()).await, a.all());
        assert_eq!(
            mongo
                .col::<Document>("messages")
                .count_documents(doc! { "_id": poisoned.as_str() })
                .await
                .unwrap(),
            1
        );
    }

    /// A run whose lease lapsed and was taken by another replica stops at
    /// the batch that finds out: that batch's rows are gone (they are
    /// deleted before the lease is advanced), nothing more is, `Done` is
    /// not written, and the new holder's lease is left as it is, live and
    /// not counting the lost run's rows. Driven through `wipe_claimed`: in
    /// `wipe_channel` the lease cannot lapse mid-run without a clock seam.
    /// Nothing is released on a lost lease; were it, the drivers release
    /// only for the holder, so it would not show.
    ///
    /// Control: the run goes on after `Batch::LeaseLost`.
    #[tokio::test]
    async fn a_lost_lease_stops_the_run_and_leaves_the_new_holder_alone() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;

        // replica-a's lease lapsed a minute ago, and replica-b took it
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-a", now_ms() - 120_000, 60_000)
                .await
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-b", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );

        // replica-a, unaware, runs on
        let outcome = wipe_claimed(&db, CHANNEL_A, "replica-a", 2, 0).await;
        assert!(matches!(outcome, Ok(Outcome::LeaseLost)), "{outcome:?}");

        let mut left = world.wiped[2..].to_vec();
        left.extend(world.survivors());
        assert_eq!(present(&db, &world.all()).await, left, "one batch only");
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Requested { .. })
        ));
        assert!(wipe_entries(&db).await.is_empty());

        // replica-b's lease is still live, and still at its own count
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-c", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-b", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );
    }

    /// A batch whose rows are read but none deleted (here another deleter
    /// took them between the read and the delete) fails as
    /// `HISTORY_WIPE_STUCK` and counts nothing. The mentions of the rows it
    /// read are gone all the same, because they are removed before the
    /// delete (F3). Driven through `wipe_rows`, the batch after its read.
    ///
    /// Controls: the stuck check dropped; the delete moved back before the
    /// mention removal.
    #[tokio::test]
    async fn a_batch_that_deletes_nothing_is_stuck_after_removing_its_mentions() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-a", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );

        let rows = db
            .fetch_history_wipe_batch(CHANNEL_A, world.boundary(), 2)
            .await
            .unwrap();
        let read: Vec<String> = rows.iter().map(|row| row.id.clone()).collect();
        assert_eq!(read, world.wiped[..2].to_vec());
        // Another deleter takes the rows first; it leaves their mentions
        assert_eq!(
            db.delete_messages_by_ids(CHANNEL_A, world.boundary(), &read)
                .await
                .unwrap(),
            2
        );
        assert_eq!(mentions(&db, CHANNEL_A).await.len(), 3);

        let error = wipe_rows(&db, CHANNEL_A, world.boundary(), "replica-a", &rows)
            .await
            .expect_err("a batch that deletes nothing must fail");
        assert!(
            matches!(error.error_type, ErrorType::InternalError),
            "{error:?}"
        );

        // The second wiped row's mention went; the rows above B keep theirs
        assert_eq!(
            mentions(&db, CHANNEL_A).await,
            vec![world.stray_above.clone(), world.encrypted_above.clone()]
        );

        // Nothing counted: the lease is still at 0
        db.release_history_wipe_lease(CHANNEL_A, "replica-a")
            .await
            .unwrap();
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-b", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );
    }

    /// 2.9: a hold set before the first batch stops the run before it reads
    /// a row. Nothing is deleted, the wipe stays `Requested`, and the lease
    /// is handed back at once with its count still 0.
    ///
    /// Control: the lease kept on a hold.
    #[tokio::test]
    async fn a_hold_before_the_first_batch_deletes_nothing_and_hands_the_lease_back() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        db.set_server_legal_hold(&hold()).await.unwrap();

        assert!(matches!(
            wipe_channel(&db, CHANNEL_A, "replica-a", 2).await,
            Ok(Outcome::Held)
        ));

        assert_eq!(present(&db, &world.all()).await, world.all());
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Requested { .. })
        ));
        assert!(wipe_entries(&db).await.is_empty());
        assert_eq!(mentions(&db, CHANNEL_A).await.len(), 3);
        assert!(db.fetch_poll(&world.poll_wiped).await.is_ok());

        // Handed back: another replica claims it at once, from 0
        assert_eq!(
            db.claim_history_wipe_lease(CHANNEL_A, "replica-b", now_ms(), LEASE_TTL_MS)
                .await
                .unwrap(),
            Some(0)
        );
    }

    /// DECISION S4-W0: with `history_setting` OFF, a wipe already
    /// `Requested` still runs to `Done`, at the configured batch size.
    ///
    /// Control: the job gated on `history_setting`.
    #[tokio::test]
    async fn a_requested_wipe_runs_to_done_with_history_setting_off() {
        let config = revolt_config::config().await;
        let protected = &config.features.protected_channels;
        assert!(
            !protected.history_setting,
            "this test pins the flag-OFF run: the test config must keep history_setting off"
        );

        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;

        let batch = i64::from(protected.history_wipe_batch_size());
        let outcomes = run_once(&db, "replica-a", batch, &mut HashSet::new()).await;
        assert_eq!(outcomes.len(), 1, "{outcomes:?}");
        assert!(
            matches!(outcomes[0].1, Ok(Outcome::Done { count: 5, .. })),
            "{outcomes:?}"
        );
        assert_eq!(present(&db, &world.all()).await, world.survivors());
        assert!(matches!(
            stored_wipe(&db, CHANNEL_A).await,
            Some(HistoryWipe::Done { count: 5, .. })
        ));
    }

    /// F4: a row whose attachment names a file with no record is wiped like
    /// any other, on both drivers. The Reference driver skips an unknown
    /// file as MongoDB's `update_many` does.
    ///
    /// Control: the Reference driver refuses an unknown file again.
    #[tokio::test]
    async fn a_row_naming_a_missing_file_is_still_wiped() {
        let (db, _guard) = test_db().await;
        let world = world(&db, CHANNEL_A, 1_000, Some(requested())).await;
        // Older than every row of the world, so it shares the first batch
        // with a row whose file exists
        let orphan = id(1_000);
        let mut row = plaintext(CHANNEL_A, &orphan);
        row.attachments = Some(vec![file("01HZXW1PEM1SS1NGF11E000000", &orphan)]);
        seed(&db, row).await;

        let (count, _, _) = done(wipe_channel(&db, CHANNEL_A, "replica-a", 2).await);
        assert_eq!(count, 6);
        assert!(present(&db, &[orphan]).await.is_empty());
        assert_eq!(present(&db, &world.all()).await, world.survivors());

        let mut want = vec![world.file_wiped.clone(), world.file_forwarded.clone()];
        want.sort();
        assert_eq!(deleted_files(&db).await, want);
    }

    const MAIN: &str = include_str!("../main.rs");

    /// A merge that drops the registration leaves the job dark with every
    /// other test green
    #[test]
    fn the_job_is_registered_inside_join() {
        let start = MAIN.find("join!(").expect("main.rs has a join!(");
        let end = start + MAIN[start..].find(");").expect("join!( is closed");
        let registration = "cron_task_wrapper(history_wipes::task, db.clone(), amqp.clone()),";

        assert_eq!(
            MAIN[start..end]
                .lines()
                .filter(|line| line.trim() == registration)
                .count(),
            1,
            "main.rs must register the history wipe job exactly once inside join!("
        );
        assert_eq!(MAIN.matches("history_wipes::task").count(), 1);
    }
}
