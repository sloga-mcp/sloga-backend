use std::collections::HashMap;
use std::time::SystemTime;
use revolt_result::Result;

use crate::{AppendMessage, FieldsMessage, Message, MessageQuery, PartialMessage};

#[cfg(feature = "mongodb")]
mod mongodb;
mod reference;

/// How far past the read pointer an unread summary looks before it gives up.
/// The reader's own messages are skipped, so without this bound a channel
/// full of them would be walked to its end on every connect. Ten caps' worth
/// only undercounts a tail holding more than that many of the reader's own
/// messages, and those clear on their next read or send.
pub const UNREAD_SCAN_WINDOW: u32 = revolt_models::v0::UNREAD_COUNT_CAP * 10;

/// What a channel's unread tail looks like, for the sidebar badge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UnreadSummary {
    /// Messages after the read pointer, saturating at `UNREAD_COUNT_CAP`
    pub count: u32,
    /// Whether any of them carries an attachment
    pub attachments: bool,
}

/// Reply count and newest message of one thread (a forum post or a thread)
///
/// Computed from the messages themselves on every call, nothing is stored,
/// so it stays exact under every delete path. System messages are NOT
/// excluded: filtering on `system` would force a document fetch, while
/// `channel` + `_id` alone are covered by the `{channel, _id}` index.
/// System messages in threads are rare and count as activity.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ThreadStats {
    /// Thread (channel) id
    pub channel: String,
    /// Messages in the thread other than its starter (the message whose id equals the thread id)
    pub replies: u32,
    /// Id of the newest message in the thread, including the starter; None if the thread has no messages
    pub last_message_id: Option<String>,
}

#[async_trait]
pub trait AbstractMessages: Sync + Send {
    /// Insert a new message into the database
    async fn insert_message(&self, message: &Message) -> Result<()>;

    /// Fetch a message by its id
    async fn fetch_message(&self, id: &str) -> Result<Message>;

    /// Fetch multiple messages by given query
    async fn fetch_messages(&self, query: MessageQuery) -> Result<Vec<Message>>;

    /// Fetch multiple messages by given IDs
    async fn fetch_messages_by_id(&self, ids: &[String]) -> Result<Vec<Message>>;

    /// Update a given message with new information
    async fn update_message(&self, id: &str, message: &PartialMessage, remove: Vec<FieldsMessage>) -> Result<()>;

    /// Append information to a given message
    async fn append_message(&self, id: &str, append: &AppendMessage) -> Result<()>;

    /// Remove a single attachment (by file id) from a message's embedded attachment list.
    /// Idempotent: succeeds even if the message or attachment no longer exists.
    async fn remove_message_attachment(&self, message_id: &str, file_id: &str) -> Result<()>;

    /// Add a new reaction to a message
    async fn add_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()>;

    /// Remove a reaction from a message
    async fn remove_reaction(&self, id: &str, emoji: &str, user: &str) -> Result<()>;

    /// Remove reaction from a message
    async fn clear_reaction(&self, id: &str, emoji: &str) -> Result<()>;

    /// Count published (Crossposted-flagged) messages in a channel whose id
    /// is at or after `min_id` — drives the durable per-channel hourly
    /// publish cap. `channel` + `_id` lead the predicate so the flag bit
    /// filter only scans one hour of one channel.
    async fn count_crossposts_since(&self, channel: &str, min_id: &str) -> Result<usize>;

    /// Count the messages `author` sent at or after `cutoff_id` (a ULID, so
    /// the string compare is a time compare) outside `exclude_channels`.
    ///
    /// Used by the daily anti-spam scan to measure a new account's public
    /// activity: the caller passes the account's DM channels as the
    /// exclusions. On MongoDB the count is hinted onto the `author` index,
    /// which stops the planner walking the `_id` range of every message sent
    /// since the cutoff.
    async fn count_author_messages_since(
        &self,
        author: &str,
        cutoff_id: &str,
        exclude_channels: &[String],
    ) -> Result<u64>;

    /// Summarise the messages sitting after a user's read pointer in a channel:
    /// how many there are (stopping at `UNREAD_COUNT_CAP`) and whether any of
    /// them carries an attachment. `after_id` is exclusive; `None` means the
    /// channel was never acknowledged, so everything counts. Messages `user`
    /// wrote themselves never count: the client leaves them out of the live
    /// count too, so a reload shows the same number. `channel` + `_id` lead
    /// the predicate and the scan stops after `UNREAD_SCAN_WINDOW` entries, so
    /// the cost per channel stays bounded however long the tail is.
    async fn summarise_unread(
        &self,
        channel: &str,
        after_id: Option<&str>,
        user: &str,
    ) -> Result<UnreadSummary>;

    /// Reply counts and newest message ids for the given threads, one entry per id in `channel_ids` (order not guaranteed)
    ///
    /// Every requested id gets an entry, even one with no messages at all
    /// (`replies: 0`, `last_message_id: None`); a repeated id gets a single
    /// entry. System messages are NOT excluded, so the query stays covered
    /// by the `{channel, _id}` index; see [`ThreadStats`].
    async fn fetch_thread_stats(&self, channel_ids: &[String]) -> Result<Vec<ThreadStats>>;

    /// Delete a message from the database by its id
    async fn delete_message(&self, id: &str) -> Result<()>;

    /// Delete messages from a channel by their ids and corresponding channel id
    async fn delete_messages(&self, channel: &str, ids: &[String]) -> Result<()>;

    /// Delete all messages from a specific author in a server from a certain ULID onwards.
    /// If the scan of matching messages fails, this returns an error before anything is
    /// marked or deleted.
    async fn delete_messages_by_author_since(
        &self,
        channels: &[String],
        author: &str,
        since: SystemTime
    ) -> Result<HashMap<String, Vec<String>>>;

    async fn delete_messages_by_user(&self, user_id: &str) -> Result<()>;

    /// One batch of the `history_wipes` job (design 7.5 "S4"): the plaintext
    /// rows of `channel` with an id at or below `boundary`, oldest first, at
    /// most `limit` of them
    ///
    /// The filter is `{ channel, _id: { $lte: boundary }, encrypted: null }`.
    /// On MongoDB `encrypted: null` matches a missing field and an explicit
    /// null, exactly the rows that decode to `encrypted: None`; the Reference
    /// driver tests `encrypted.is_none()`. A row carrying `encrypted` is never
    /// returned, whatever its id. Ids compare as strings (ULIDs sort by time).
    ///
    /// Sorted by `_id` ascending, so a job that stopped between this read and
    /// the delete resumes on the same rows. `limit` is clamped to at least 1
    /// and a row that does not decode fails the call instead of being skipped:
    /// an empty answer must only ever mean nothing is left to wipe.
    async fn fetch_history_wipe_batch(
        &self,
        channel: &str,
        boundary: &str,
        limit: i64,
    ) -> Result<Vec<Message>>;

    /// Delete the listed plaintext rows of `channel`; returns how many went
    ///
    /// Scoped to `channel` AND `encrypted: null` as well as to the ids, so a
    /// wrong id list can never delete a row carrying `encrypted` or another
    /// channel's row. No cascade: attachments, polls, softres sheets and
    /// unread mentions are the caller's (the `history_wipes` job).
    async fn delete_messages_by_ids(&self, channel: &str, ids: &[String]) -> Result<u64>;

    /// Id of the newest row of `channel`, encrypted or not; None when it has none
    async fn fetch_newest_message_id(&self, channel: &str) -> Result<Option<String>>;
}

#[cfg(test)]
mod tests {
    use crate::{Message, PartialMessage};
    use revolt_models::v0;

    /// Minimal attachment — only its presence matters to the unread summary.
    fn attachment_file(seed: u64) -> crate::File {
        crate::File {
            id: format!("01FILE{seed:021}"),
            tag: "attachments".to_string(),
            filename: "note.txt".to_string(),
            hash: None,
            uploaded_at: None,
            uploader_id: None,
            used_for: None,
            deleted: None,
            reported: None,
            metadata: crate::Metadata::File,
            content_type: "text/plain".to_string(),
            size: 1,
            message_id: None,
            user_id: None,
            server_id: None,
            object_id: None,
        }
    }

    /// Whoever is reading the channel in the unread-summary tests. Not the
    /// author of the fixture messages, so every one of them counts.
    const READER: &str = "01READER00000000000000000000";

    fn button(id: &str) -> v0::Component {
        v0::Component::Button {
            custom_id: id.to_string(),
            label: "Click".to_string(),
            style: v0::ButtonStyle::Primary,
            disabled: false,
        }
    }

    #[tokio::test]
    async fn components_survive_insert_and_partial_update() {
        database_test!(|db| async move {
            let message = Message {
                id: "01MESSAGE000000000000000000".to_string(),
                channel: "01CHANNEL000000000000000000".to_string(),
                author: "01BOT0000000000000000000000".to_string(),
                content: Some("pick one".to_string()),
                components: Some(vec![v0::ActionRow {
                    components: vec![button("a")],
                }]),
                ..Default::default()
            };
            db.insert_message(&message).await.unwrap();

            let fetched = db.fetch_message(&message.id).await.unwrap();
            assert_eq!(fetched.components, message.components);

            // A components-carrying partial must not silently drop the
            // field on either driver (component edit-responses depend on
            // update_message fanning the new rows out).
            let partial = PartialMessage {
                components: Some(vec![v0::ActionRow {
                    components: vec![button("b"), button("c")],
                }]),
                ..Default::default()
            };
            db.update_message(&message.id, &partial, vec![])
                .await
                .unwrap();

            let updated = db.fetch_message(&message.id).await.unwrap();
            assert_eq!(updated.components, partial.components);
            assert_eq!(
                updated.content, message.content,
                "unrelated fields must be untouched"
            );
        });
    }

    #[tokio::test]
    async fn count_crossposts_since_scopes_by_channel_time_and_flag() {
        database_test!(|db| async move {
            use revolt_models::v0::MessageFlags;
            let crossposted = 1_u32 << (MessageFlags::Crossposted as u32);
            let is_crosspost = 1_u32 << (MessageFlags::IsCrosspost as u32);

            let channel = "01CHANXPOST0000000000000001";
            let other_channel = "01CHANXPOST0000000000000002";

            // `rand` keeps ids unique even when two rows share a timestamp.
            let mk = |ms: u64, rand: u128, flags: Option<u32>, chan: &str| Message {
                id: ulid::Ulid::from_parts(ms, rand).to_string(),
                channel: chan.to_string(),
                author: "01USER000000000000000000000".to_string(),
                content: Some("published".to_string()),
                flags,
                ..Default::default()
            };

            // 12 published messages at ms 2000, 3000 .. 13000 in the channel.
            for i in 0..12u64 {
                db.insert_message(&mk(2_000 + i * 1_000, 1, Some(crossposted), channel))
                    .await
                    .unwrap();
            }
            // An OLD published message before the window.
            db.insert_message(&mk(500, 2, Some(crossposted), channel))
                .await
                .unwrap();
            // A non-published message in-window (no Crossposted flag).
            db.insert_message(&mk(2_500, 3, None, channel))
                .await
                .unwrap();
            // A delivered crosspost copy (IsCrosspost, NOT Crossposted) must
            // not count toward the source's publish cap.
            db.insert_message(&mk(2_600, 4, Some(is_crosspost), channel))
                .await
                .unwrap();
            // A published message in another channel must not leak in.
            db.insert_message(&mk(3_000, 5, Some(crossposted), other_channel))
                .await
                .unwrap();

            // Window lower bound at ms 1000 catches all 12 (>10 → cap tripped).
            let min_id = ulid::Ulid::from_parts(1_000, 0).to_string();
            assert_eq!(
                db.count_crossposts_since(channel, &min_id).await.unwrap(),
                12
            );

            // A tighter lower bound drops the earliest publishes from the count.
            let tighter = ulid::Ulid::from_parts(8_000, 0).to_string();
            assert_eq!(
                db.count_crossposts_since(channel, &tighter).await.unwrap(),
                6
            );
        });
    }

    /// The daily anti-spam scan's public-activity count: only the author's
    /// messages, only from the cutoff on, never in an excluded channel.
    #[tokio::test]
    async fn count_author_messages_since_scopes_by_author_time_and_channel() {
        database_test!(|db| async move {
            let author = "01SPAMAUTHOR00000000000000";
            let other = "01OTHERAUTHOR0000000000000";
            let c1 = "01CHANSPAM0000000000000001";
            let c2 = "01CHANSPAM0000000000000002";
            let c3 = "01CHANSPAM0000000000000003";

            // `rand` keeps ids unique even when two rows share a timestamp.
            let mk = |ms: u64, rand: u128, chan: &str, by: &str| Message {
                id: ulid::Ulid::from_parts(ms, rand).to_string(),
                channel: chan.to_string(),
                author: by.to_string(),
                content: Some("hello".to_string()),
                ..Default::default()
            };
            let cutoff = ulid::Ulid::from_parts(1_000, 0).to_string();

            let rows = [
                // From the cutoff on: two in c1, three in c2, one in c3.
                mk(2_000, 1, c1, author),
                mk(3_000, 2, c1, author),
                mk(2_000, 3, c2, author),
                mk(4_000, 4, c2, author),
                mk(5_000, 5, c2, author),
                mk(6_000, 6, c3, author),
                // Exactly at the cutoff: the bound is inclusive.
                mk(1_000, 0, c3, author),
                // Before the cutoff, in channels that are counted.
                mk(500, 7, c2, author),
                mk(999, 8, c3, author),
                // Someone else, after the cutoff, in a counted channel.
                mk(2_500, 9, c2, other),
            ];
            for row in &rows {
                db.insert_message(row).await.unwrap();
            }

            let count = |by: &'static str, since: String, exclude: Vec<&'static str>| {
                let db = db.clone();
                async move {
                    let exclude: Vec<String> = exclude.into_iter().map(str::to_string).collect();
                    db.count_author_messages_since(by, &since, &exclude)
                        .await
                        .unwrap()
                }
            };

            // c1 stands in for the account's DMs: excluded, c2 + c3 remain.
            assert_eq!(count(author, cutoff.clone(), vec![c1]).await, 5);
            assert_eq!(count(author, cutoff.clone(), vec![]).await, 7);
            assert_eq!(count(author, cutoff.clone(), vec![c1, c2, c3]).await, 0);
            assert_eq!(count(other, cutoff.clone(), vec![]).await, 1);
            assert_eq!(
                count("01NOBODY000000000000000000", cutoff.clone(), vec![]).await,
                0
            );

            // A later cutoff drops the earlier messages: c2 at 5_000, c3 at 6_000.
            let later = ulid::Ulid::from_parts(4_500, 0).to_string();
            assert_eq!(count(author, later, vec![c1]).await, 2);
        });
    }

    #[tokio::test]
    async fn summarise_unread_scopes_by_channel_and_read_pointer() {
        database_test!(|db| async move {
            use revolt_models::v0::UNREAD_COUNT_CAP;

            let channel = "01CHANUNREAD0000000000000001";
            let other_channel = "01CHANUNREAD0000000000000002";

            let mk = |ms: u64, rand: u128, chan: &str, attachment: bool| Message {
                id: ulid::Ulid::from_parts(ms, rand).to_string(),
                channel: chan.to_string(),
                author: "01USER000000000000000000000".to_string(),
                content: Some("hello".to_string()),
                attachments: attachment.then(|| vec![attachment_file(ms)]),
                ..Default::default()
            };

            // Five plain messages at ms 1000, 2000 .. 5000.
            for i in 0..5u64 {
                db.insert_message(&mk(1_000 + i * 1_000, 1, channel, false))
                    .await
                    .unwrap();
            }
            // Another channel's traffic must not leak in.
            db.insert_message(&mk(3_000, 9, other_channel, true))
                .await
                .unwrap();

            // No read pointer — everything in the channel counts.
            let all = db.summarise_unread(channel, None, READER).await.unwrap();
            assert_eq!(all.count, 5);
            assert!(!all.attachments);

            // The pointer is exclusive: acking ms 3000 leaves 4000 and 5000.
            let pointer = ulid::Ulid::from_parts(3_000, 1).to_string();
            let tail = db
                .summarise_unread(channel, Some(&pointer), READER)
                .await
                .unwrap();
            assert_eq!(tail.count, 2);
            assert!(!tail.attachments);

            // An attachment anywhere in the tail raises the flag, and one
            // before the pointer does not.
            db.insert_message(&mk(500, 2, channel, true)).await.unwrap();
            db.insert_message(&mk(4_500, 3, channel, true))
                .await
                .unwrap();
            assert!(
                db.summarise_unread(channel, Some(&pointer), READER)
                    .await
                    .unwrap()
                    .attachments
            );
            let late = ulid::Ulid::from_parts(4_600, 0).to_string();
            assert!(
                !db.summarise_unread(channel, Some(&late), READER)
                    .await
                    .unwrap()
                    .attachments
            );

            // The count saturates rather than walking the whole tail.
            let deep = "01CHANUNREAD0000000000000003";
            for i in 0..(UNREAD_COUNT_CAP as u64 + 5) {
                db.insert_message(&mk(10_000 + i, 1, deep, false))
                    .await
                    .unwrap();
            }
            assert_eq!(
                db.summarise_unread(deep, None, READER).await.unwrap().count,
                UNREAD_COUNT_CAP
            );
        });
    }

    #[tokio::test]
    async fn summarise_unread_skips_the_readers_own_messages() {
        database_test!(|db| async move {
            let channel = "01CHANUNREAD0000000000000004";
            let other = "01OTHERAUTHOR0000000000000";

            let mk = |ms: u64, author: &str, attachment: bool| Message {
                id: ulid::Ulid::from_parts(ms, 1).to_string(),
                channel: channel.to_string(),
                author: author.to_string(),
                content: Some("hello".to_string()),
                attachments: attachment.then(|| vec![attachment_file(ms)]),
                ..Default::default()
            };

            // Past the pointer: two of someone else's, then two of the
            // reader's own, one of which carries the only attachment.
            db.insert_message(&mk(1_000, other, false)).await.unwrap();
            db.insert_message(&mk(2_000, other, false)).await.unwrap();
            db.insert_message(&mk(3_000, READER, true)).await.unwrap();
            db.insert_message(&mk(4_000, READER, false)).await.unwrap();

            let summary = db.summarise_unread(channel, None, READER).await.unwrap();
            assert_eq!(summary.count, 2, "only the other author's messages count");
            assert!(
                !summary.attachments,
                "an attachment on the reader's own message raises no flag"
            );

            // The same tail read by someone else counts everything.
            let theirs = db.summarise_unread(channel, None, other).await.unwrap();
            assert_eq!(theirs.count, 2, "the other author's own two drop out");
            assert!(theirs.attachments);
            let bystander = db
                .summarise_unread(channel, None, "01BYSTANDER000000000000000")
                .await
                .unwrap();
            assert_eq!(bystander.count, 4);

            // A tail made only of the reader's own messages is empty.
            let pointer = ulid::Ulid::from_parts(2_000, 1).to_string();
            assert_eq!(
                db.summarise_unread(channel, Some(&pointer), READER)
                    .await
                    .unwrap(),
                Default::default()
            );
        });
    }

    #[tokio::test]
    async fn summarise_unread_caps_count_and_scan_around_own_messages() {
        database_test!(|db| async move {
            use super::UNREAD_SCAN_WINDOW;
            use revolt_models::v0::UNREAD_COUNT_CAP;

            let other = "01OTHERAUTHOR0000000000000";
            let mk = |ms: u64, chan: &str, author: &str| Message {
                id: ulid::Ulid::from_parts(ms, 1).to_string(),
                channel: chan.to_string(),
                author: author.to_string(),
                content: Some("hello".to_string()),
                ..Default::default()
            };

            // The cap applies to the other author's messages, not to the raw
            // tail: every third message is the reader's own, and there are
            // still more than a cap's worth of the rest.
            let mixed = "01CHANUNREAD0000000000000005";
            for i in 0..(UNREAD_COUNT_CAP as u64 * 2) {
                let author = if i % 3 == 0 { READER } else { other };
                db.insert_message(&mk(1_000 + i, mixed, author))
                    .await
                    .unwrap();
            }
            assert_eq!(
                db.summarise_unread(mixed, None, READER)
                    .await
                    .unwrap()
                    .count,
                UNREAD_COUNT_CAP
            );

            // Own messages ahead of a single foreign one still let it count.
            let ahead = "01CHANUNREAD0000000000000006";
            for i in 0..20u64 {
                db.insert_message(&mk(5_000 + i, ahead, READER))
                    .await
                    .unwrap();
            }
            db.insert_message(&mk(6_000, ahead, other)).await.unwrap();
            assert_eq!(
                db.summarise_unread(ahead, None, READER)
                    .await
                    .unwrap()
                    .count,
                1
            );

            // The scan is bounded: a foreign message sitting behind a whole
            // window of the reader's own is not reached, by design.
            let deep = "01CHANUNREAD0000000000000007";
            for i in 0..(UNREAD_SCAN_WINDOW as u64) {
                db.insert_message(&mk(10_000 + i, deep, READER))
                    .await
                    .unwrap();
            }
            db.insert_message(&mk(20_000, deep, other)).await.unwrap();
            assert_eq!(
                db.summarise_unread(deep, None, READER).await.unwrap().count,
                0,
                "the scan stops after UNREAD_SCAN_WINDOW messages"
            );
        });
    }

    /// The ban purge removes only the author's messages in the listed channels
    /// from `since` onwards, reports them per channel, and marks only their
    /// attachments deleted.
    #[tokio::test]
    async fn delete_messages_by_author_since_scopes_and_marks_attachments() {
        database_test!(|db| async move {
            use revolt_result::ErrorType;
            use std::collections::HashMap;
            use std::time::{Duration, SystemTime};

            let author = "01PURGEAUTHOR0000000000000";
            let other = "01OTHERAUTHOR0000000000000";
            let chan_a = "01CHANPURGE0000000000000001";
            let chan_b = "01CHANPURGE0000000000000002";
            let chan_c = "01CHANPURGE0000000000000003";
            // Hits sit at 2_000 ms or later and the early control at 500 ms,
            // never at 1_000 ms: `since` gets random bits on its way to a ULID.
            let since = SystemTime::UNIX_EPOCH + Duration::from_secs(1);

            let mk = |ms: u64, rand: u128, chan: &str, by: &str| Message {
                id: ulid::Ulid::from_parts(ms, rand).to_string(),
                channel: chan.to_string(),
                author: by.to_string(),
                content: Some("purge me".to_string()),
                ..Default::default()
            };

            let hit_file = attachment_file(7_100_001);
            let early_file = attachment_file(7_100_002);
            db.insert_attachment(&hit_file).await.unwrap();
            db.insert_attachment(&early_file).await.unwrap();

            let hit_a1 = Message {
                attachments: Some(vec![hit_file.clone()]),
                ..mk(2_000, 1, chan_a, author)
            };
            let hit_a2 = mk(3_000, 2, chan_a, author);
            let hit_b = mk(2_500, 3, chan_b, author);
            // Before `since`, by someone else, and in a channel not passed in.
            let early = Message {
                attachments: Some(vec![early_file.clone()]),
                ..mk(500, 4, chan_a, author)
            };
            let other_author = mk(2_000, 5, chan_a, other);
            let unlisted = mk(2_000, 6, chan_c, author);

            let hits = [&hit_a1, &hit_a2, &hit_b];
            let controls = [&early, &other_author, &unlisted];
            for message in hits.iter().chain(controls.iter()) {
                db.insert_message(message).await.unwrap();
            }

            let listed = [chan_a.to_string(), chan_b.to_string()];
            let mut deleted = db
                .delete_messages_by_author_since(&listed, author, since)
                .await
                .unwrap();
            // Neither driver promises an order within a channel.
            for ids in deleted.values_mut() {
                ids.sort();
            }
            let mut in_a = vec![hit_a1.id.clone(), hit_a2.id.clone()];
            in_a.sort();
            let expected = HashMap::from([
                (chan_a.to_string(), in_a),
                (chan_b.to_string(), vec![hit_b.id.clone()]),
            ]);
            assert_eq!(deleted, expected);

            for hit in hits {
                let fetched = db.fetch_message(&hit.id).await;
                assert!(
                    matches!(&fetched, Err(e) if matches!(e.error_type, ErrorType::NotFound)),
                    "hit {} survived the purge: {fetched:?}",
                    hit.id
                );
            }
            for control in controls {
                assert!(
                    db.fetch_message(&control.id).await.is_ok(),
                    "control {} was purged",
                    control.id
                );
            }

            let marked = db
                .fetch_attachment("attachments", &hit_file.id)
                .await
                .unwrap();
            assert_eq!(marked.deleted, Some(true), "the hit's attachment is marked");
            let kept = db
                .fetch_attachment("attachments", &early_file.id)
                .await
                .unwrap();
            assert_eq!(kept.deleted, None, "a surviving message's attachment stays");
        });
    }

    /// A row the purge cannot decode fails the whole call before any write:
    /// nothing is marked or deleted, so the moderator can retry. Mongo only;
    /// the Reference driver has no cursor to fail, so there it returns early.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn delete_messages_by_author_since_fails_closed_on_undecodable_row() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Document};
            use revolt_result::ErrorType;
            use std::collections::HashMap;
            use std::time::{Duration, SystemTime};

            let author = "01PURGEAUTHOR0000000000000";
            let good_chan = "01CHANPURGE0000000000000004";
            let bad_chan = "01CHANPURGE0000000000000005";
            let since = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
            let messages = mongo.col::<Document>("messages");

            let file = attachment_file(7_200_001);
            db.insert_attachment(&file).await.unwrap();
            let good = Message {
                id: ulid::Ulid::from_parts(2_000, 1).to_string(),
                channel: good_chan.to_string(),
                author: author.to_string(),
                content: Some("purge me".to_string()),
                attachments: Some(vec![file.clone()]),
                ..Default::default()
            };
            db.insert_message(&good).await.unwrap();

            // An Int32 attachment id passes the pipeline (`$setUnion` keeps
            // it) but cannot decode into `AggregatedChannel.attachment_ids:
            // Vec<String>`, so its row comes off the cursor as an Err. It sits
            // in a second channel because the pipeline emits one row per
            // channel: in the good message's channel it would poison that row
            // too, the unfixed code would mark nothing, and the "not marked"
            // check below would pass vacuously. Never read it back through
            // `fetch_message` or `fetch_messages`: their typed reads unwrap in
            // debug and would panic on it.
            let bad_id = ulid::Ulid::from_parts(3_000, 2).to_string();
            messages
                .insert_one(doc! {
                    "_id": bad_id.as_str(),
                    "channel": bad_chan,
                    "author": author,
                    "attachments": [{ "_id": 5_i32, "tag": "attachments" }]
                })
                .await
                .expect("insert the poisoned message");

            let listed = [good_chan.to_string(), bad_chan.to_string()];
            let err = db
                .delete_messages_by_author_since(&listed, author, since)
                .await
                .expect_err("an undecodable row must fail the purge, not be skipped");
            assert!(
                matches!(
                    &err.error_type,
                    ErrorType::DatabaseError { operation, collection }
                        if operation == "aggregate" && collection == "messages"
                ),
                "{err:?}"
            );

            // Counted raw: a typed read would trip over the poisoned doc.
            let left = messages
                .count_documents(doc! { "_id": { "$in": [good.id.as_str(), bad_id.as_str()] } })
                .await
                .unwrap();
            assert_eq!(left, 2, "a failed purge must delete nothing");
            let unmarked = db.fetch_attachment("attachments", &file.id).await.unwrap();
            assert_eq!(unmarked.deleted, None, "a failed purge must mark nothing");

            // With the poisoned doc gone the same call goes through, which
            // pins the error on that row.
            messages
                .delete_one(doc! { "_id": bad_id.as_str() })
                .await
                .unwrap();
            let deleted = db
                .delete_messages_by_author_since(&listed, author, since)
                .await
                .expect("the purge succeeds once the poisoned doc is gone");
            assert_eq!(
                deleted,
                HashMap::from([(good_chan.to_string(), vec![good.id.clone()])])
            );
            let marked = db.fetch_attachment("attachments", &file.id).await.unwrap();
            assert_eq!(marked.deleted, Some(true), "the good attachment is marked");
        });
    }

    /// A message deleted while its embeds were being fetched must not get a
    /// `MessageAppend`: clients would be told about embeds on a message that
    /// no longer exists. Holds on both drivers, for an empty append as well
    /// as a real one. Needs Redis at `REDIS_URI`.
    #[tokio::test]
    async fn append_to_missing_message_is_not_found_and_publishes_nothing() {
        database_test!(|db| async move {
            use crate::events::client::EventV1;
            use crate::AppendMessage;
            use futures::StreamExt;
            use revolt_result::ErrorType;
            use std::time::Duration;

            // A fresh topic per run, so nothing else ever publishes to it.
            let channel = ulid::Ulid::new().to_string();
            let mut pubsub = redis_kiss::open_pubsub_connection()
                .await
                .expect("pubsub connection");
            pubsub.subscribe(&channel).await.expect("subscribe");
            let mut stream = pubsub.on_message();

            let missing_id = ulid::Ulid::new().to_string();
            let err = Message::append(
                &db,
                missing_id.clone(),
                channel.clone(),
                AppendMessage {
                    embeds: Some(vec![v0::Embed::None]),
                },
            )
            .await
            .expect_err("append to a missing message must be NotFound");
            assert!(matches!(err.error_type, ErrorType::NotFound), "{err:?}");
            let fetched = db.fetch_message(&missing_id).await;
            assert!(
                matches!(&fetched, Err(e) if matches!(e.error_type, ErrorType::NotFound)),
                "append must not create the message: {fetched:?}"
            );

            // An empty append may succeed or fail, but must stay silent.
            let _ = Message::append(
                &db,
                missing_id.clone(),
                channel.clone(),
                AppendMessage {
                    embeds: Some(vec![]),
                },
            )
            .await;

            // Positive control: a live message does get its event, which also
            // proves the subscription is actually receiving.
            let live = Message {
                id: ulid::Ulid::new().to_string(),
                channel: channel.clone(),
                author: "01USER000000000000000000000".to_string(),
                content: Some("hello".to_string()),
                ..Default::default()
            };
            db.insert_message(&live).await.unwrap();
            Message::append(
                &db,
                live.id.clone(),
                channel.clone(),
                AppendMessage {
                    embeds: Some(vec![v0::Embed::None]),
                },
            )
            .await
            .expect("append to a live message");
            let appended = db.fetch_message(&live.id).await.unwrap();
            assert_eq!(appended.embeds.expect("embeds").len(), 1);

            // Drain the topic: wait for the live event, then give anything
            // trailing a second to show up.
            let mut seen: Vec<(String, String)> = Vec::new();
            let mut live_seen = false;
            loop {
                let wait = Duration::from_secs(if live_seen { 1 } else { 5 });
                let msg = match tokio::time::timeout(wait, stream.next()).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break,
                    Err(_) if live_seen => break,
                    Err(_) => panic!(
                        "positive control: no MessageAppend received (is Redis at REDIS_URI up?)"
                    ),
                };
                let event = redis_kiss::decode_payload::<EventV1>(&msg)
                    .expect("undecodable payload on the channel topic");
                match event {
                    EventV1::MessageAppend { id, .. } => {
                        live_seen |= id == live.id;
                        seen.push(("MessageAppend".to_string(), id));
                    }
                    other => seen.push(("other".to_string(), format!("{other:?}"))),
                }
            }
            assert_eq!(
                seen,
                vec![("MessageAppend".to_string(), live.id.clone())],
                "ghost or unexpected events on the channel topic"
            );
        });
    }

    /// A structurally valid `encrypted` payload; only its presence matters
    /// to the wipe driver fns
    fn wipe_payload(seed: u8) -> crate::EncryptedPayload {
        use crate::EncryptedPayload;
        use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

        EncryptedPayload {
            v: EncryptedPayload::VERSION,
            group_id: "ab".repeat(32),
            epoch: 0,
            sender_device_id: "cd".repeat(16),
            nonce: STANDARD_NO_PAD.encode([seed; EncryptedPayload::NONCE_BYTES]),
            ciphertext: STANDARD_NO_PAD.encode([seed; EncryptedPayload::CIPHERTEXT_MIN_BYTES]),
            sig: STANDARD_NO_PAD.encode([seed; EncryptedPayload::SIG_BYTES]),
            franking: None,
        }
    }

    /// A wipe fixture row: plaintext, or carrying `encrypted` when `seed` is set
    fn wipe_row(ms: u64, rand: u128, channel: &str, seed: Option<u8>) -> Message {
        Message {
            id: ulid::Ulid::from_parts(ms, rand).to_string(),
            channel: channel.to_string(),
            author: "01USER000000000000000000000".to_string(),
            content: seed.is_none().then(|| "before protect".to_string()),
            nonce: seed.map(|seed| format!("01JA00000000000000000000{seed:02}")),
            encrypted: seed.map(wipe_payload),
            ..Default::default()
        }
    }

    /// Store a row as-is, past `insert_message`'s protected-shape check, so a
    /// fixture can hold what a buggy or hostile writer could leave behind
    async fn insert_raw(db: &crate::Database, message: &Message) {
        match db {
            crate::Database::Reference(reference) => {
                reference
                    .messages
                    .lock()
                    .await
                    .insert(message.id.clone(), message.clone());
            }
            #[cfg(feature = "mongodb")]
            crate::Database::MongoDb(mongo) => {
                mongo
                    .col::<Message>("messages")
                    .insert_one(message)
                    .await
                    .expect("raw insert");
            }
        }
    }

    async fn exists(db: &crate::Database, id: &str) -> bool {
        db.fetch_message(id).await.is_ok()
    }

    fn wipe_ids(batch: &[Message]) -> Vec<String> {
        batch.iter().map(|message| message.id.clone()).collect()
    }

    /// The wipe batch takes the rows at or below the boundary, the boundary
    /// row itself included, oldest first, never more than the limit and never
    /// nothing because of the limit; the delete reports what it removed.
    #[tokio::test]
    async fn wipe_batch_respects_the_boundary_and_the_limit() {
        database_test!(|db| async move {
            let channel = "01CHANWIPE0000000000000001";
            let rows: Vec<Message> = (1..=5u64)
                .map(|i| wipe_row(i * 1_000, 1, channel, None))
                .collect();
            // Stored newest first, so the order of an answer is the sort's
            for row in rows.iter().rev() {
                insert_raw(&db, row).await;
            }
            let id = |i: usize| rows[i].id.clone();
            let boundary = id(2);

            let batch = db
                .fetch_history_wipe_batch(channel, &boundary, 100)
                .await
                .unwrap();
            assert_eq!(
                wipe_ids(&batch),
                vec![id(0), id(1), id(2)],
                "the row at B is in the batch, the rows above it are not"
            );

            let batch = db
                .fetch_history_wipe_batch(channel, &boundary, 2)
                .await
                .unwrap();
            assert_eq!(wipe_ids(&batch), vec![id(0), id(1)], "oldest first");

            for limit in [0, -5] {
                let batch = db
                    .fetch_history_wipe_batch(channel, &boundary, limit)
                    .await
                    .unwrap();
                assert_eq!(
                    wipe_ids(&batch),
                    vec![id(0)],
                    "limit {limit} is clamped to 1"
                );
            }

            // Just below the B row's id leaves that row out
            let below = ulid::Ulid::from_parts(3_000, 0).to_string();
            let batch = db
                .fetch_history_wipe_batch(channel, &below, 100)
                .await
                .unwrap();
            assert_eq!(wipe_ids(&batch), vec![id(0), id(1)]);

            let listed = [id(0), id(1), id(2)];
            assert_eq!(
                db.delete_messages_by_ids(channel, &listed).await.unwrap(),
                3
            );
            assert_eq!(
                db.delete_messages_by_ids(channel, &listed).await.unwrap(),
                0,
                "a repeat deletes nothing"
            );
            assert_eq!(db.delete_messages_by_ids(channel, &[]).await.unwrap(), 0);
            assert!(db
                .fetch_history_wipe_batch(channel, &boundary, 100)
                .await
                .unwrap()
                .is_empty());
            for i in [3, 4] {
                assert!(exists(&db, &id(i)).await, "row {i} above B was touched");
            }
        });
    }

    /// The hostile fixture (design 11 "Backend, wipe"): a row carrying
    /// `encrypted` with an id at or below B is never returned or deleted, not
    /// even when the delete lists it, and neither is another channel's row
    /// whose id is listed.
    #[tokio::test]
    async fn wipe_never_touches_an_encrypted_row_or_another_channel() {
        database_test!(|db| async move {
            let channel = "01CHANWIPE0000000000000002";
            let other = "01CHANWIPE0000000000000003";
            let oldest = wipe_row(1_000, 1, channel, None);
            let injected = wipe_row(1_500, 1, channel, Some(1));
            let at_boundary = wipe_row(2_000, 1, channel, None);
            let above = wipe_row(2_500, 1, channel, Some(2));
            let elsewhere = wipe_row(1_200, 1, other, None);
            for row in [&oldest, &injected, &at_boundary, &above, &elsewhere] {
                insert_raw(&db, row).await;
            }
            let boundary = at_boundary.id.clone();

            let batch = db
                .fetch_history_wipe_batch(channel, &boundary, 100)
                .await
                .unwrap();
            assert_eq!(
                wipe_ids(&batch),
                vec![oldest.id.clone(), at_boundary.id.clone()],
                "the encrypted row at or below B must never be in a batch"
            );

            // A wrong list: every id of the fixture
            let listed = [
                oldest.id.clone(),
                injected.id.clone(),
                at_boundary.id.clone(),
                above.id.clone(),
                elsewhere.id.clone(),
            ];
            assert_eq!(
                db.delete_messages_by_ids(channel, &listed).await.unwrap(),
                2,
                "only the channel's two plaintext rows may go"
            );
            assert!(!exists(&db, &oldest.id).await);
            assert!(!exists(&db, &at_boundary.id).await);
            assert!(
                exists(&db, &injected.id).await,
                "an encrypted row at or below B was deleted"
            );
            assert!(
                exists(&db, &above.id).await,
                "an encrypted row above B was deleted"
            );
            assert!(
                exists(&db, &elsewhere.id).await,
                "another channel's listed row was deleted"
            );

            assert!(db
                .fetch_history_wipe_batch(channel, &boundary, 100)
                .await
                .unwrap()
                .is_empty());
            let theirs = db
                .fetch_history_wipe_batch(other, &boundary, 100)
                .await
                .unwrap();
            assert_eq!(wipe_ids(&theirs), vec![elsewhere.id.clone()]);
        });
    }

    /// MongoDB's `encrypted: null` also matches an explicit null, which
    /// decodes to `encrypted: None`: such a row is plaintext to the wipe as it
    /// is to the read rule. Mongo only; the Reference driver stores typed rows.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn wipe_treats_an_explicit_null_encrypted_as_plaintext() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Bson, Document};

            let channel = "01CHANWIPE0000000000000004";
            let row = wipe_row(1_000, 1, channel, None);
            let mut raw = bson::to_document(&row).expect("encode the row");
            raw.insert("encrypted", Bson::Null);
            let messages = mongo.col::<Document>("messages");
            messages.insert_one(raw).await.expect("insert the row");
            assert_eq!(
                messages
                    .count_documents(
                        doc! { "_id": row.id.as_str(), "encrypted": { "$type": "null" } }
                    )
                    .await
                    .unwrap(),
                1,
                "the fixture must store an explicit null"
            );
            assert!(db.fetch_message(&row.id).await.unwrap().encrypted.is_none());

            let batch = db
                .fetch_history_wipe_batch(channel, &row.id, 10)
                .await
                .unwrap();
            assert_eq!(wipe_ids(&batch), vec![row.id.clone()]);
            assert_eq!(
                db.delete_messages_by_ids(channel, std::slice::from_ref(&row.id))
                    .await
                    .unwrap(),
                1
            );
        });
    }

    /// A row the batch cannot decode fails the call instead of vanishing from
    /// it: a batch that silently loses rows could come back empty while
    /// plaintext is left. Mongo only; the Reference driver stores typed rows.
    #[cfg(feature = "mongodb")]
    #[tokio::test]
    async fn wipe_batch_fails_closed_on_an_undecodable_row() {
        database_test!(|db| async move {
            let crate::Database::MongoDb(mongo) = &db else {
                return;
            };
            use bson::{doc, Document};
            use revolt_result::ErrorType;

            let channel = "01CHANWIPE0000000000000005";
            let good = wipe_row(1_000, 1, channel, None);
            insert_raw(&db, &good).await;
            // An Int32 author cannot decode into `Message.author: String`
            let bad_id = ulid::Ulid::from_parts(2_000, 1).to_string();
            mongo
                .col::<Document>("messages")
                .insert_one(doc! { "_id": bad_id.as_str(), "channel": channel, "author": 5_i32 })
                .await
                .expect("insert the poisoned row");

            let err = db
                .fetch_history_wipe_batch(channel, &bad_id, 10)
                .await
                .expect_err("an undecodable row must fail the batch, not be skipped");
            assert!(
                matches!(
                    &err.error_type,
                    ErrorType::DatabaseError { operation, collection }
                        if operation == "find" && collection == "messages"
                ),
                "{err:?}"
            );

            // With the poisoned row out of range the same call goes through
            let batch = db
                .fetch_history_wipe_batch(channel, &good.id, 10)
                .await
                .unwrap();
            assert_eq!(wipe_ids(&batch), vec![good.id.clone()]);
        });
    }

    /// The newest row decides `last_message_id` after a wipe: an encrypted
    /// row counts, another channel's does not, and an emptied channel has none.
    #[tokio::test]
    async fn wipe_newest_message_id_follows_the_newest_row() {
        database_test!(|db| async move {
            let channel = "01CHANWIPE0000000000000006";
            let other = "01CHANWIPE0000000000000007";
            assert_eq!(db.fetch_newest_message_id(channel).await.unwrap(), None);

            let first = wipe_row(1_000, 1, channel, None);
            let newest = wipe_row(3_000, 1, channel, Some(3));
            let middle = wipe_row(2_000, 1, channel, None);
            let elsewhere = wipe_row(9_000, 1, other, None);
            for row in [&first, &newest, &middle, &elsewhere] {
                insert_raw(&db, row).await;
            }

            assert_eq!(
                db.fetch_newest_message_id(channel).await.unwrap(),
                Some(newest.id.clone())
            );
            db.delete_message(&newest.id).await.unwrap();
            assert_eq!(
                db.fetch_newest_message_id(channel).await.unwrap(),
                Some(middle.id.clone())
            );
            db.delete_messages_by_ids(channel, &[first.id.clone(), middle.id.clone()])
                .await
                .unwrap();
            assert_eq!(db.fetch_newest_message_id(channel).await.unwrap(), None);
            assert_eq!(
                db.fetch_newest_message_id(other).await.unwrap(),
                Some(elsewhere.id.clone())
            );
        });
    }
}
