// Queue Type: Debounced
use crate::{Database, Message, AMQP};

use deadqueue::limited::Queue;
use futures::FutureExt;
use once_cell::sync::Lazy;
use revolt_config::capture_message;
use revolt_models::v0::PushNotification;
use std::{
    collections::{HashMap, HashSet},
    panic::AssertUnwindSafe,
    time::Duration,
};
use validator::HasLen;

use revolt_result::{ErrorType, Result};

use super::DelayedTask;
use crate::Channel::{TextChannel, Thread};

/// Enumeration of possible events
#[derive(Debug, Eq, PartialEq)]
pub enum AckEvent {
    /// Add mentions for a channel
    ProcessMessage {
        /// push notification, message, recipients, push silenced
        messages: Vec<(Option<PushNotification>, Message, Vec<String>, bool)>,
    },

    /// Acknowledge message in a channel for a user
    AckMessage {
        /// Message ID
        id: String,
    },
}

/// Task information
struct Data {
    /// Channel to ack
    channel: String,
    /// User to ack for
    user: Option<String>,
    /// Event
    event: AckEvent,
}

#[derive(Debug)]
struct Task {
    event: AckEvent,
}

static Q: Lazy<Queue<Data>> = Lazy::new(|| Queue::new(10_000));

/// Queue a new task for a worker
pub async fn queue_ack(channel: String, user: String, event: AckEvent) {
    Q.try_push(Data {
        channel,
        user: Some(user),
        event,
    })
    .ok();

    info!(
        "Queue is using {} slots from {}. Queued type: ACK",
        Q.len(),
        Q.capacity()
    );
}

/// Do not add more than one message per event.
pub async fn queue_message(channel: String, event: AckEvent) {
    Q.try_push(Data {
        channel,
        user: None,
        event,
    })
    .ok();

    info!(
        "Queue is using {} slots from {}. Queued type: MENTION",
        Q.len(),
        Q.capacity()
    );
}

/// Find the server a mass mention in `channel_id` fans out to.
///
/// Returns `None` when there is nothing to fan out to, and the caller then
/// skips the mass mention push for this batch. That covers a channel that was
/// deleted between the message being sent and the debounced batch running
/// (logged, not reported, since it is an expected race), a failed fetch, and a
/// channel type that cannot carry a mass mention.
async fn mass_mention_server(db: &Database, channel_id: &str) -> Option<String> {
    match db.fetch_channel(channel_id).await {
        // Threads carry their server id directly, so mass mentions in a
        // thread fan out the same way as in a text channel.
        Ok(TextChannel { server, .. } | Thread { server, .. }) => Some(server),
        Ok(_) => {
            capture_message(
                "Unknown channel type when sending mass mention event",
                revolt_config::Level::Error,
            );
            None
        }
        Err(err) if matches!(err.error_type, ErrorType::NotFound) => {
            warn!("Channel {channel_id} is gone; skipping mass mention push");
            None
        }
        Err(err) => {
            error!("Failed to fetch channel {channel_id} for a mass mention push: {err:?}");
            revolt_config::capture_error(&err);
            None
        }
    }
}

pub async fn handle_ack_event(
    event: &AckEvent,
    db: &Database,
    amqp: &AMQP,
    user: &Option<String>,
    channel: &str,
) -> Result<()> {
    match &event {
        #[allow(clippy::disallowed_methods)] // event is sent by higher level function
        AckEvent::AckMessage { id } => {
            let user = user.as_ref().unwrap();
            let user: &str = user.as_str();

            let unread = db.fetch_unread(user, channel).await?;
            let updated = db.acknowledge_message(channel, user, id).await?;

            if let (Some(before), Some(after)) = (unread, updated) {
                let before_mentions = before.mentions.unwrap_or_default().len();
                let after_mentions = after.mentions.unwrap_or_default().len();

                if after_mentions < before_mentions {
                    if let Err(err) = amqp
                        .ack_notification_message(
                            user.to_string(),
                            channel.to_string(),
                            id.to_owned(),
                        )
                        .await
                    {
                        revolt_config::capture_error(&err);
                    }
                };
            }
        }
        AckEvent::ProcessMessage { messages } => {
            let mut users: HashSet<&String> = HashSet::new();
            info!(
                "Processing {} messages from channel {}",
                messages.len(),
                messages[0].1.channel
            );

            // find all the users we'll be notifying
            messages.iter().for_each(|(_, _, recipents, _)| {
                users.extend(recipents.iter());
            });

            info!("Found {} users to notify.", users.len());

            for user in users {
                let message_ids: Vec<String> = messages
                    .iter()
                    .filter_map(|(_, message, recipients, _)| {
                        if recipients.contains(user) {
                            Some(message.id.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                if !message_ids.is_empty() {
                    db.add_mention_to_unread(channel, user, &message_ids)
                        .await?;
                }
                info!("Added {} mentions for user {}", message_ids.len(), &user);
            }

            let mut mass_mentions = vec![];

            for (push, message, recipients, silenced) in messages {
                if *silenced
                    || push.is_none()
                    || (recipients.is_empty() && !message.contains_mass_push_mention())
                {
                    debug!(
                        "Rejecting push: silenced: {}, recipient count: {}, push exists: {:?}",
                        *silenced,
                        recipients.length(),
                        push.is_some()
                    );
                    continue;
                }

                debug!(
                    "Sending push event to AMQP; message {} for {} users",
                    push.as_ref().unwrap().message.id,
                    recipients.len()
                );
                if let Err(err) = amqp
                    .message_sent(recipients.clone(), push.clone().unwrap())
                    .await
                {
                    revolt_config::capture_error(&err);
                }

                if message.contains_mass_push_mention() {
                    mass_mentions.push(push.clone().unwrap());
                }
            }

            if !mass_mentions.is_empty() {
                debug!(
                    "Sending mass mention push event to AMQP; channel {}",
                    &mass_mentions[0].message.channel
                );

                // The per-user mentions and direct pushes above have already
                // gone out. If the channel cannot be resolved to a server (for
                // example it was deleted while this batch sat in the debounce
                // window), only this batch's mass mention fan-out is dropped.
                if let Some(server) =
                    mass_mention_server(db, &mass_mentions[0].message.channel).await
                {
                    if let Err(err) = amqp.mass_mention_message_sent(server, mass_mentions).await {
                        revolt_config::capture_error(&err);
                    }
                }
            }
        }
    };

    Ok(())
}

/// Describe a batch for an error report without any message or push content:
/// only the event kind and the message ids.
fn event_ids(event: &AckEvent) -> (&'static str, Vec<&str>) {
    match event {
        AckEvent::ProcessMessage { messages } => (
            "ProcessMessage",
            messages
                .iter()
                .map(|(_, message, _, _)| message.id.as_str())
                .collect(),
        ),
        AckEvent::AckMessage { id } => ("AckMessage", vec![id.as_str()]),
    }
}

/// Start a new worker
pub async fn worker(db: Database, amqp: AMQP) {
    let mut tasks = HashMap::<(Option<String>, String, u8), DelayedTask<Task>>::new();
    let mut keys: Vec<(Option<String>, String, u8)> = vec![];

    loop {
        // Find due tasks.
        for (key, task) in &tasks {
            if task.should_run() {
                keys.push(key.clone());
            }
        }

        // Commit any due tasks to the database.
        for key in &keys {
            if let Some(task) = tasks.remove(key) {
                let Task { event } = task.data;
                let (user, channel, _) = key;

                // A panic in one batch must not take the worker down with it:
                // the batch has already been removed from `tasks`, so the rest
                // of the debounce map is intact and the loop carries on.
                let outcome = AssertUnwindSafe(handle_ack_event(&event, &db, &amqp, user, channel))
                    .catch_unwind()
                    .await;

                match outcome {
                    Ok(Ok(())) => info!("User {user:?} ack in {channel} with {event:?}"),
                    Ok(Err(err)) => {
                        revolt_config::capture_error(&err);
                        error!("{err:?} for {event:?}. ({user:?}, {channel})");
                    }
                    Err(payload) => {
                        let msg = super::panic_message(&*payload);
                        error!("Ack batch panicked: {msg} for {event:?}. ({user:?}, {channel})");

                        // Ids only: message and push bodies must never reach
                        // the error reporter.
                        let (kind, message_ids) = event_ids(&event);
                        revolt_config::capture_message(
                            &format!(
                                "Ack batch panicked: {msg} (kind: {kind}, channel: {channel}, user: {user:?}, messages: {message_ids:?})"
                            ),
                            revolt_config::Level::Error,
                        );
                    }
                }
            }
        }

        // Clear keys
        keys.clear();

        // Queue incoming tasks.
        while let Some(Data {
            channel,
            user,
            mut event,
        }) = Q.try_pop()
        {
            info!("Took next ack from queue, now {} remaining", Q.len());

            let key: (Option<String>, String, u8) = (
                user,
                channel,
                match &event {
                    AckEvent::AckMessage { .. } => 0,
                    AckEvent::ProcessMessage { .. } => 1,
                },
            );
            if let Some(task) = tasks.get_mut(&key) {
                match &mut event {
                    AckEvent::ProcessMessage { messages: new_data } => {
                        if let AckEvent::ProcessMessage { messages: existing } =
                            &mut task.data.event
                        {
                            if let Some(new_event) = new_data.pop() {
                                // if the message contains a mass mention, do not delay it any further.
                                if new_event.1.contains_mass_push_mention() {
                                    // add the new message to the list of messages to be processed.
                                    existing.push(new_event);
                                    task.run_immediately();
                                    continue;
                                }

                                existing.push(new_event);

                                // put a cap on the amount of messages that can be queued, for particularly active channels
                                if (existing.length() as u16)
                                    < revolt_config::config()
                                        .await
                                        .features
                                        .advanced
                                        .process_message_delay_limit
                                {
                                    task.delay();
                                }
                            } else {
                                let err_msg = format!("Got zero-length message event: {event:?}");
                                capture_message(&err_msg, revolt_config::Level::Warning);
                                info!("{err_msg}")
                            }
                        } else {
                            panic!("Somehow got an ack message in the add mention arm");
                        }
                    }
                    AckEvent::AckMessage { .. } => {
                        // replace the last acked message with the new acked message
                        task.data.event = event;
                        task.delay();
                    }
                }
            } else {
                tasks.insert(key, DelayedTask::new(Task { event }));
            }
        }

        // Sleep for an arbitrary amount of time.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Channel, DatabaseInfo};

    fn text_channel(id: &str, server: &str) -> Channel {
        Channel::TextChannel {
            id: id.to_string(),
            server: server.to_string(),
            name: "general".to_string(),
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
        }
    }

    fn thread(id: &str, server: &str, parent: &str) -> Channel {
        Channel::Thread {
            id: id.to_string(),
            server: server.to_string(),
            parent_channel: parent.to_string(),
            name: "thread".to_string(),
            creator: new_id(),
            origin_message_id: None,
            last_message_id: None,
            archived: false,
            archived_timestamp: None,
            auto_archive_minutes: 0,
            locked: false,
            applied_tags: vec![],
        }
    }

    fn new_id() -> String {
        ulid::Ulid::new().to_string()
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn mass_mention_server_skips_a_deleted_channel() {
        database_test!(|db| async move {
            // A thread, because the MongoDB `delete_channel` looks up the
            // server of a text channel (or forum) and this test has no server.
            let id = new_id();
            let channel = thread(&id, &new_id(), &new_id());
            db.insert_channel(&channel).await.unwrap();
            db.delete_channel(&channel).await.unwrap();

            assert_eq!(mass_mention_server(&db, &id).await, None);
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn mass_mention_server_finds_a_text_channel_server() {
        database_test!(|db| async move {
            let id = new_id();
            let server = new_id();
            db.insert_channel(&text_channel(&id, &server))
                .await
                .unwrap();

            assert_eq!(mass_mention_server(&db, &id).await, Some(server));
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn mass_mention_server_finds_a_thread_server() {
        database_test!(|db| async move {
            let parent = new_id();
            let id = new_id();
            let server = new_id();
            db.insert_channel(&text_channel(&parent, &server))
                .await
                .unwrap();
            db.insert_channel(&thread(&id, &server, &parent))
                .await
                .unwrap();

            assert_eq!(mass_mention_server(&db, &id).await, Some(server));
        });
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)]
    async fn mass_mention_server_skips_a_direct_message() {
        database_test!(|db| async move {
            let id = new_id();
            db.insert_channel(&Channel::DirectMessage {
                id: id.clone(),
                active: true,
                recipients: vec![new_id(), new_id()],
                last_message_id: None,
            })
            .await
            .unwrap();

            assert_eq!(mass_mention_server(&db, &id).await, None);
        });
    }

    /// One worker (not `start_workers`, whose five workers and supervisors
    /// would hide a single death) is fed a mass mention batch for a channel
    /// that does not exist, then a witness batch on another channel. The
    /// worker must still be alive and must process the witness.
    ///
    /// Nothing is published: m0 and m2 carry no push, m1 has no recipients
    /// (`message_sent` returns early), and the mass fan-out is skipped
    /// because the channel fetch fails.
    #[tokio::test]
    #[ignore = "needs a local RabbitMQ at the Revolt.test.toml address (AMQP::new_auto) and TEST_DB=REFERENCE"]
    async fn ack_worker_survives_a_mass_mention_to_a_deleted_channel() {
        assert_eq!(std::env::var("TEST_DB").as_deref(), Ok("REFERENCE"));

        let db = DatabaseInfo::Reference.connect().await.unwrap();
        let amqp = AMQP::new_auto().await;

        // Channel X is never inserted, so fetching it returns NotFound.
        let x = new_id();
        let x_channel = text_channel(&x, &new_id());
        let y = new_id();
        let user = new_id();

        let m0 = Message {
            id: new_id(),
            channel: x.clone(),
            author: new_id(),
            ..Default::default()
        };
        let m1 = Message {
            id: new_id(),
            channel: x.clone(),
            author: new_id(),
            role_mentions: Some(vec![new_id()]),
            ..Default::default()
        };
        assert!(m1.contains_mass_push_mention());
        let push = PushNotification::from(
            m1.clone().into_model(None, None),
            None,
            x_channel.clone().into(),
        )
        .await;

        // Both are taken in the worker's first pass: the second merges into
        // the first and marks it to run immediately, on the next pass.
        queue_message(
            x.clone(),
            AckEvent::ProcessMessage {
                messages: vec![(None, m0, vec![], false)],
            },
        )
        .await;
        queue_message(
            x.clone(),
            AckEvent::ProcessMessage {
                messages: vec![(Some(push), m1, vec![], false)],
            },
        )
        .await;

        let handle = tokio::spawn(worker(db.clone(), amqp.clone()));

        tokio::time::sleep(Duration::from_secs(3)).await;
        if handle.is_finished() {
            let panicked = handle.await.unwrap_err().is_panic();
            panic!("the ack worker died on the mass mention batch (panicked: {panicked})");
        }

        let m2 = Message {
            id: new_id(),
            channel: y.clone(),
            author: new_id(),
            ..Default::default()
        };
        let m2_id = m2.id.clone();
        queue_message(
            y.clone(),
            AckEvent::ProcessMessage {
                messages: vec![(None, m2, vec![user.clone()], false)],
            },
        )
        .await;

        let mut arrived = false;
        for _ in 0..48 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let unread = db.fetch_unread(&user, &y).await.unwrap();
            if unread.and_then(|unread| unread.mentions) == Some(vec![m2_id.clone()]) {
                arrived = true;
                break;
            }
        }

        let alive = !handle.is_finished();
        handle.abort();

        assert!(arrived, "the witness mention never arrived");
        assert!(alive, "the ack worker died after processing the witness");
    }
}
