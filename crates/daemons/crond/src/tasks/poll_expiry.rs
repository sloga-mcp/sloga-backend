use std::time::{Duration, SystemTime, UNIX_EPOCH};

use revolt_database::{Database, Poll, ProtectedReadView, AMQP};
use revolt_result::{ErrorType, Result};
use tokio::time::sleep;

/// How often the poll expiry scan runs. Lazy close-on-vote/fetch in the
/// delta routes covers the (up to one tick) gap and daemon downtime, and
/// every close path funnels through `Poll::close`'s atomic flip, so the
/// `PollClose` event fires exactly once regardless of who closes first.
const POLL_TICK: Duration = Duration::from_secs(60);

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Close expired polls and publish their final results.
pub async fn task(db: Database, _amqp: AMQP) -> Result<()> {
    loop {
        let closed = run_once(&db, now_ms()).await?;

        if closed > 0 {
            log::info!("Closed {closed} expired poll(s)");
        }

        sleep(POLL_TICK).await
    }
}

/// One scan: close every open poll expired at `now`, and return how many
/// this scan closed. `PollClose` is published only for a poll whose parent
/// message is servable (design 7.4 "S4", ruling R-FANOUT): the poll of a
/// wipe-pending row is closed without an event, like the poll of a row
/// that is gone.
pub async fn run_once(db: &Database, now: i64) -> Result<usize> {
    let due = db.fetch_expired_open_polls(now).await?;

    let mut closed = 0usize;
    for poll in due {
        let close = match poll_is_servable(db, &poll).await {
            // Publishes PollClose when this scan wins the flip
            Ok(true) => poll.close(db).await.map(|won| won.is_some()),
            Ok(false) => close_quietly(db, &poll).await,
            Err(err) => Err(err),
        };

        match close {
            // This tick won the close
            Ok(true) => closed += 1,
            // Lost the race to a lazy close: nothing to do
            Ok(false) => {}
            // The poll stays open and the next tick tries again
            Err(err) => {
                revolt_config::capture_error(&err);
            }
        }
    }

    Ok(closed)
}

/// Whether the final results of `poll` may be published: only while its
/// parent message is servable under its channel's read view, the rule the
/// poll routes apply (`poll_fetch::poll_is_servable` in delta, over
/// `Message::is_servable`). The channel is read for its view; only a
/// protected one reads the parent. A missing channel, thread parent or
/// parent message is not servable.
async fn poll_is_servable(db: &Database, poll: &Poll) -> Result<bool> {
    let channel = match db.fetch_channel(&poll.channel).await {
        Ok(channel) => channel,
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    let permission_channel = match channel.permission_target(db).await {
        Ok(target) => target.into_owned(),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };

    let view = ProtectedReadView::of_read_target(&channel, &permission_channel);
    if !view.protected {
        return Ok(true);
    }

    match db.fetch_message(&poll.message).await {
        Ok(message) => Ok(message.is_servable(&view)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

/// `Poll::close` without the event: the same atomic flip and recount from
/// the ballots, so the close stays exactly once against the lazy closes and
/// `/end`. Whether this scan won the flip.
async fn close_quietly(db: &Database, poll: &Poll) -> Result<bool> {
    if !db.close_poll_if_open(&poll.id).await? {
        return Ok(false);
    }

    poll.recount(db).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    //! Database tests run on the driver `TEST_DB` names, REFERENCE and
    //! MONGODB (never without it). Published events are read off Redis on
    //! the channel's topic, up to a sentinel published after the scan, so
    //! an event the scan published is always read before it.

    use std::collections::HashMap;

    use futures::StreamExt;
    use revolt_database::{
        events::client::EventV1, test_teardown::TestDatabaseGuard, Channel, DatabaseInfo,
        EncryptedPayload, HistoryWipe, Message, ProtectedHistory,
    };
    use revolt_models::v0;

    use super::*;

    const SERVER: &str = "01HZXW1PESERVER00000000000";
    const USER: &str = "01HZXW1PEUSER0000000000000";

    /// Not a poll id, so it never stands for a real close
    const SENTINEL: &str = "poll-expiry-test-sentinel";

    /// A fresh test database on the driver `TEST_DB` names, in the harness
    /// name shape the guard drops when the test ends
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

    /// A channel id no other test run shares, so its topic is this test's
    fn channel_id() -> String {
        ulid::Ulid::new().to_string()
    }

    fn text_channel(
        channel_id: &str,
        protected: bool,
        history: Option<ProtectedHistory>,
    ) -> Channel {
        Channel::TextChannel {
            id: channel_id.to_string(),
            server: SERVER.to_string(),
            name: "polls".to_string(),
            description: None,
            icon: None,
            last_message_id: None,
            default_permissions: None,
            role_permissions: HashMap::new(),
            nsfw: false,
            spoiler: false,
            voice: None,
            slowmode: None,
            announcement: None,
            protected,
            protected_history: history.map(Box::new),
        }
    }

    fn plaintext(channel_id: &str, message_id: &str) -> Message {
        Message {
            id: message_id.to_string(),
            channel: channel_id.to_string(),
            author: USER.to_string(),
            content: Some("which crab".to_string()),
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

    /// Store a message straight through the driver: `insert_message`
    /// refuses plaintext on a protected channel, and these rows predate it
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

    /// An open poll on `message_id` that expired long ago
    async fn expired_poll(db: &Database, channel_id: &str, message_id: &str) -> String {
        let poll_id = format!("{message_id}-POLL");
        db.insert_poll(&Poll {
            id: poll_id.clone(),
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
            expires_at: 1_000,
            closed: false,
            counts: HashMap::new(),
            total_votes: 0,
        })
        .await
        .unwrap();
        poll_id
    }

    /// Run one scan while subscribed to the topics of `channels`, and return
    /// how many it closed and the poll ids of the `PollClose` events it
    /// published, in order
    async fn scan_and_read_poll_closes(db: &Database, channels: &[&str]) -> (usize, Vec<String>) {
        // Sets REDIS_URI for redis-kiss when the environment has none
        revolt_config::config().await;
        let mut pubsub = redis_kiss::open_pubsub_connection()
            .await
            .expect("a Redis pubsub connection");
        for channel in channels {
            pubsub.subscribe(*channel).await.expect("subscribe");
        }

        let closed = run_once(db, now_ms()).await.expect("the scan");

        let last = channels.last().expect("a channel").to_string();
        EventV1::PollClose {
            id: SENTINEL.to_string(),
            channel_id: last.clone(),
            message_id: SENTINEL.to_string(),
            counts: vec![],
            total_votes: 0,
        }
        .p(last)
        .await;

        let mut published = Vec::new();
        let mut messages = pubsub.on_message();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(30), messages.next())
                .await
                .expect("the sentinel did not arrive")
                .expect("the subscription ended");
            if let Ok(EventV1::PollClose { id, .. }) =
                redis_kiss::decode_payload::<EventV1>(&message)
            {
                if id == SENTINEL {
                    break;
                }
                published.push(id);
            }
        }

        (closed, published)
    }

    async fn is_closed(db: &Database, poll_id: &str) -> bool {
        db.fetch_poll(poll_id).await.unwrap().closed
    }

    /// R-FANOUT: an expired poll whose parent is a wipe-pending plaintext
    /// row (at or below B, wipe `Requested`) is closed with no `PollClose`.
    /// The poll of a ciphertext row in the same channel is servable and
    /// still gets its event.
    ///
    /// Control: the scan always publishes.
    #[tokio::test]
    async fn an_expired_poll_on_a_wipe_pending_row_closes_without_poll_close() {
        let (db, _guard) = test_db().await;
        let channel = channel_id();
        let (row, boundary, cipher) = (id(1_000), id(2_000), id(3_000));
        db.insert_channel(&text_channel(
            &channel,
            true,
            Some(ProtectedHistory {
                boundary: boundary.clone(),
                wipe: HistoryWipe::Requested {
                    at: iso8601_timestamp::Timestamp::UNIX_EPOCH,
                    by: USER.to_string(),
                },
            }),
        ))
        .await
        .unwrap();
        seed(&db, plaintext(&channel, &row)).await;
        seed(&db, encrypted(&channel, &cipher)).await;
        let pending = expired_poll(&db, &channel, &row).await;
        let servable = expired_poll(&db, &channel, &cipher).await;

        let (closed, published) = scan_and_read_poll_closes(&db, &[&channel]).await;

        assert_eq!(closed, 2);
        assert!(is_closed(&db, &pending).await);
        assert!(is_closed(&db, &servable).await);
        assert_eq!(published, vec![servable]);
    }

    /// An expired poll on an unprotected channel is closed and its
    /// `PollClose` published as before, and so is one on a servable
    /// plaintext row of a protected channel (at or below B, not wiped).
    ///
    /// Control: the scan never publishes.
    #[tokio::test]
    async fn an_expired_poll_on_a_servable_row_publishes_poll_close() {
        let (db, _guard) = test_db().await;
        let open = channel_id();
        let kept = channel_id();
        let (row, open_row, boundary) = (id(1_000), id(1_500), id(2_000));

        db.insert_channel(&text_channel(&open, false, None))
            .await
            .unwrap();
        db.insert_channel(&text_channel(
            &kept,
            true,
            Some(ProtectedHistory {
                boundary,
                wipe: HistoryWipe::None,
            }),
        ))
        .await
        .unwrap();
        seed(&db, plaintext(&open, &open_row)).await;
        seed(&db, plaintext(&kept, &row)).await;
        let unprotected = expired_poll(&db, &open, &open_row).await;
        let protected = expired_poll(&db, &kept, &row).await;

        let (closed, mut published) = scan_and_read_poll_closes(&db, &[&open, &kept]).await;

        assert_eq!(closed, 2);
        assert!(is_closed(&db, &unprotected).await);
        assert!(is_closed(&db, &protected).await);
        published.sort();
        let mut want = vec![unprotected, protected];
        want.sort();
        assert_eq!(published, want);
    }
}
