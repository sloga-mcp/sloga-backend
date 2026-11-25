use std::collections::HashSet;
use std::sync::Arc;

use crate::events::rabbit::*;
use crate::User;
use lapin::{
    options::BasicPublishOptions,
    protocol::basic::AMQPProperties,
    types::{AMQPValue, FieldTable},
    Channel, Connection, ConnectionProperties, Error as AMQPError,
};
use revolt_models::v0::PushNotification;
use revolt_presence::filter_online;
use revolt_result::Result;

use serde_json::to_string;

#[derive(Clone)]
pub struct AMQP {
    friend_request_accepted: Arc<Channel>,
    friend_request_received: Arc<Channel>,
    generic_message: Arc<Channel>,
    message_sent: Arc<Channel>,
    mass_mention_message_sent: Arc<Channel>,
    ack_notification_message: Arc<Channel>,
    dm_call_updated: Arc<Channel>,
    calendar_event: Arc<Channel>,
    process_ack: Arc<Channel>,
    #[allow(unused)]
    connection: Arc<Connection>,
}

/// One signal about a ringing DM or group call, as handed to the push daemon.
/// `recipients` narrows who is told; `None` tells everyone in the conversation.
/// `ended` refers to the ringing period, not necessarily the call itself.
#[derive(Debug, Clone, Default)]
pub struct DmCallSignal {
    pub initiator_id: String,
    pub channel_id: String,
    pub started_at: Option<String>,
    pub ended: bool,
    pub recipients: Option<Vec<String>>,
    /// Identifies one ring; every later signal about that ring repeats it
    pub call_id: Option<String>,
    /// Why the ringing stopped; only ever set together with `ended = true`
    pub reason: Option<String>,
    /// Whether the caller started a video call
    pub video: Option<bool>,
}

/// How long a stop-ringing signal stays worth delivering. It only matters while a phone
/// may still be ringing, so it outlives a ring by a little and no more.
const DM_CALL_ENDED_EXPIRATION_MS: usize = 60_000;

/// The per-message expiration for a DM call signal, in milliseconds, as the decimal
/// string AMQP carries it in. A ring is worth delivering only for as long as the caller
/// is still ringing; a stop-ringing signal gets a fixed minute.
///
/// `ring_secs` is the configured ring length as it stands. It is read through
/// `revolt_config::effective_call_ring_secs`, the rule every service shares, so a zero
/// (which would expire every ring the instant it is queued) rings for the default 45
/// seconds, and no setting can keep a ring queued for longer than a call may ring.
pub fn dm_call_expiration_ms(ended: bool, ring_secs: usize) -> String {
    if ended {
        return DM_CALL_ENDED_EXPIRATION_MS.to_string();
    }

    revolt_config::effective_call_ring_secs(ring_secs)
        .saturating_mul(1000)
        .to_string()
}

impl AMQP {
    pub async fn new(connection: Arc<Connection>) -> Self {
        Self {
            friend_request_accepted: Self::create_channel(&connection).await,
            friend_request_received: Self::create_channel(&connection).await,
            generic_message: Self::create_channel(&connection).await,
            message_sent: Self::create_channel(&connection).await,
            mass_mention_message_sent: Self::create_channel(&connection).await,
            ack_notification_message: Self::create_channel(&connection).await,
            dm_call_updated: Self::create_channel(&connection).await,
            calendar_event: Self::create_channel(&connection).await,
            process_ack: Self::create_channel(&connection).await,
            connection,
        }
    }

    pub async fn new_auto() -> Self {
        let config = revolt_config::config().await;

        let connection = Arc::new(
            Connection::connect(
                &format!(
                    "amqp://{}:{}@{}:{}",
                    &config.rabbit.username,
                    &config.rabbit.password,
                    &config.rabbit.host,
                    &config.rabbit.port,
                ),
                ConnectionProperties::default(),
            )
            .await
            .expect("Failed to connect to RabbitMQ"),
        );

        Self::new(connection).await
    }

    async fn create_channel(connection: &Connection) -> Arc<Channel> {
        Arc::new(
            connection
                .create_channel()
                .await
                .expect("Failed to create channel"),
        )
    }

    pub async fn friend_request_accepted(
        &self,
        accepted_request_user: &User,
        sent_request_user: &User,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let payload = FRAcceptedPayload {
            accepted_user: accepted_request_user.to_owned(),
            user: sent_request_user.id.clone(),
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending friend request accept payload on channel {}: {}",
            config.pushd.get_fr_accepted_routing_key(),
            payload
        );

        self.friend_request_accepted
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.get_fr_accepted_routing_key().into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    pub async fn friend_request_received(
        &self,
        received_request_user: &User,
        sent_request_user: &User,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let payload = FRReceivedPayload {
            from_user: sent_request_user.to_owned(),
            user: received_request_user.id.clone(),
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending friend request received payload on channel {}: {}",
            config.pushd.get_fr_received_routing_key(),
            payload
        );

        self.friend_request_received
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.get_fr_received_routing_key().into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    pub async fn generic_message(
        &self,
        user: &User,
        title: String,
        body: String,
        icon: Option<String>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let payload = GenericPayload {
            title,
            body,
            icon,
            user: user.to_owned(),
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending generic payload on channel {}: {}",
            config.pushd.get_generic_routing_key(),
            payload
        );

        self.generic_message
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.get_generic_routing_key().into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    pub async fn message_sent(
        &self,
        recipients: Vec<String>,
        payload: PushNotification,
    ) -> Result<(), AMQPError> {
        if recipients.is_empty() {
            return Ok(());
        }

        let config = revolt_config::config().await;

        let online_ids = filter_online(&recipients).await;
        let recipients = (&recipients.into_iter().collect::<HashSet<String>>() - &online_ids)
            .into_iter()
            .collect::<Vec<String>>();

        let payload = MessageSentPayload {
            notification: payload,
            users: recipients,
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending message payload on channel {}: {}",
            config.pushd.get_message_routing_key(),
            payload
        );

        self.message_sent
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.get_message_routing_key().into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    pub async fn mass_mention_message_sent(
        &self,
        server_id: String,
        payload: Vec<PushNotification>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = MassMessageSentPayload {
            notifications: payload,
            server_id,
        };
        let payload = to_string(&payload).unwrap();

        let routing_key = config.pushd.get_mass_mention_routing_key();

        debug!(
            "Sending mass mention payload on channel {}: {}",
            routing_key, payload
        );

        self.mass_mention_message_sent
            .basic_publish(
                config.pushd.exchange.clone().into(),
                routing_key.into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    /// # Sends an ack to pushd to update badges on iPhones.
    /// Not to be confused with the process_ack function, which handles sending all acks to crond for processing.
    pub async fn ack_notification_message(
        &self,
        user_id: String,
        channel_id: String,
        message_id: String,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = AckPayload {
            user_id: user_id.clone(),
            channel_id: channel_id.clone(),
            message_id,
        };
        let payload = to_string(&payload).unwrap();

        info!(
            "Sending ack payload on channel {}: {}",
            config.pushd.ack_queue, payload
        );

        let mut headers = FieldTable::default();
        headers.insert(
            "x-deduplication-header".into(),
            AMQPValue::LongString(format!("{}-{}", &user_id, &channel_id).into()),
        );

        self.ack_notification_message
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.ack_queue.into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    /// # DM Call Update
    /// Used to send an update about a DM call, eg. start or end of a call.
    /// Recipients can be used to narrow the scope of recipients, otherwise all recipients will be notified.
    /// `ended` refers to the ringing period, not necessarily the call itself.
    pub async fn dm_call_updated(
        &self,
        initiator_id: &str,
        channel_id: &str,
        started_at: Option<&str>,
        ended: bool,
        recipients: Option<Vec<String>>,
    ) -> Result<(), AMQPError> {
        self.dm_call_signal(DmCallSignal {
            initiator_id: initiator_id.to_string(),
            channel_id: channel_id.to_string(),
            started_at: started_at.map(|f| f.to_string()),
            ended,
            recipients,
            ..Default::default()
        })
        .await
    }

    /// # DM Call Signal
    /// Sends one signal about a ringing DM or group call to the push daemon.
    /// Every signal is published with an expiration: one that sat in the queue while the
    /// push daemon was down is dropped by the broker instead of ringing a phone, or
    /// silencing a newer ring, long after the moment it was about.
    pub async fn dm_call_signal(&self, signal: DmCallSignal) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let DmCallSignal {
            initiator_id,
            channel_id,
            started_at,
            ended,
            recipients,
            call_id,
            reason,
            video,
        } = signal;

        let expiration = dm_call_expiration_ms(ended, config.api.livekit.call_ring_duration);

        let payload = InternalDmCallPayload {
            payload: DmCallPayload {
                initiator_id,
                channel_id,
                started_at,
                ended,
                call_id,
                reason,
                video,
            },
            recipients,
        };
        let payload = to_string(&payload).unwrap();

        debug!(
            "Sending dm call update payload on channel {}: {}",
            config.pushd.get_dm_call_routing_key(),
            payload
        );

        self.dm_call_updated
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.get_dm_call_routing_key().into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2)
                    .with_expiration(expiration.into()),
            )
            .await?;

        Ok(())
    }

    /// # Calendar event notification
    /// Enqueue a single per-recipient calendar-event push (invite / cancel / reminder).
    /// One message per recipient — pushd fans it out to that user's subscribed sessions.
    /// Delivery is intentionally offline-agnostic (reminders/cancels must reach devices
    /// that are not connected), so there is no online filtering here (design §9).
    pub async fn calendar_event_notify(
        &self,
        payload: &CalendarEventPayload,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;
        let body = to_string(payload).unwrap();

        debug!(
            "Sending calendar event payload on channel {}: {}",
            config.pushd.get_calendar_event_routing_key(),
            body
        );

        self.calendar_event
            .basic_publish(
                config.pushd.exchange.clone().into(),
                config.pushd.get_calendar_event_routing_key().into(),
                BasicPublishOptions::default(),
                body.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }

    /// # Send an ack to crond for processing
    pub async fn process_ack(
        &self,
        user_id: &str,
        channel_id: Option<&str>,
        server_id: Option<&str>,
    ) -> Result<(), AMQPError> {
        let config = revolt_config::config().await;

        let payload = AckEventPayload {
            user_id: user_id.to_string(),
            channel_id: channel_id.map(|value| value.to_string()),
            server_id: server_id.map(|value| value.to_string()),
        };
        let payload = to_string(&payload).unwrap();

        info!(
            "Sending ack processor event on exchange {}, channel {}: {}",
            config.rabbit.default_exchange, config.rabbit.queues.acks, payload
        );

        self.process_ack
            .basic_publish(
                config.rabbit.default_exchange.clone().into(),
                config.rabbit.queues.acks.into(),
                BasicPublishOptions::default(),
                payload.as_bytes(),
                AMQPProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2),
            )
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod dm_call_tests {
    use super::dm_call_expiration_ms;

    const SOURCE: &str = include_str!("amqp.rs");

    /// Everything above this test module: the shipping source.
    fn shipping() -> &'static str {
        let end = SOURCE
            .find("#[cfg(test)]")
            .expect("the test module marker is in this file");
        &SOURCE[..end]
    }

    /// One method of `AMQP`, from its signature to the start of the next method.
    fn method_source(name: &str) -> &'static str {
        let shipping = shipping();
        let start = shipping
            .find(&format!("pub async fn {}(", name))
            .unwrap_or_else(|| panic!("AMQP::{} is gone", name));
        let rest = &shipping[start..];
        let end = rest[1..]
            .find("pub async fn ")
            .map(|at| at + 1)
            .unwrap_or(rest.len());
        &rest[..end]
    }

    #[test]
    fn dm_call_expiration_truth_table() {
        let cases = [
            // a ring lives as long as the caller rings
            (false, 45, "45000"),
            (false, 30, "30000"),
            // a zero ring length falls back instead of expiring the ring at once
            (false, 0, "45000"),
            // a ring length outside what a call may ring for is brought to the nearest end
            (false, 1, "5000"),
            (false, 5, "5000"),
            (false, 120, "120000"),
            (false, 121, "120000"),
            (false, 100_000, "120000"),
            (false, usize::MAX, "120000"),
            // a stop-ringing signal gets a fixed minute, whatever the ring length
            (true, 45, "60000"),
            (true, 30, "60000"),
            (true, 0, "60000"),
            (true, 300, "60000"),
            (true, usize::MAX, "60000"),
        ];

        for (ended, ring_secs, expected) in cases {
            let expiration = dm_call_expiration_ms(ended, ring_secs);
            assert_eq!(
                expiration, expected,
                "ended = {}, ring_secs = {}",
                ended, ring_secs
            );
            // The broker refuses a publish whose expiration is not a plain whole number.
            assert!(
                !expiration.is_empty() && expiration.bytes().all(|b| b.is_ascii_digit()),
                "expiration {:?} is not a plain whole number",
                expiration
            );
        }
    }

    /// A ring must leave the queue exactly when the apps stop ringing, so its expiration
    /// is the ring length every service reads, not a rule of this file's own.
    #[test]
    fn a_ring_expires_after_the_ring_length_every_service_reads() {
        for ring_secs in [0, 1, 4, 5, 6, 44, 45, 46, 119, 120, 121, 3600, usize::MAX] {
            let shared = revolt_config::effective_call_ring_secs(ring_secs);
            assert_eq!(
                dm_call_expiration_ms(false, ring_secs),
                (shared * 1000).to_string(),
                "ring_secs = {}",
                ring_secs
            );
        }
    }

    /// The expiration only helps if the publish carries it, and nothing here can publish to
    /// a broker, so the source is pinned instead: the one publish of a DM call signal sets
    /// an expiration computed from the configured ring length.
    #[test]
    fn dm_call_signal_publishes_with_the_expiration() {
        let signal = method_source("dm_call_signal");

        assert!(
            signal
                .contains("dm_call_expiration_ms(ended, config.api.livekit.call_ring_duration)"),
            "dm_call_signal must take its expiration from the configured ring length"
        );
        assert!(
            signal.contains(".with_expiration(expiration.into())"),
            "dm_call_signal must publish with the expiration"
        );
        assert_eq!(
            signal.matches(".basic_publish(").count(),
            1,
            "dm_call_signal must publish exactly once"
        );
    }

    /// The older entry point must not grow a publish of its own again, or its signals
    /// would go out without the expiration.
    #[test]
    fn dm_call_updated_goes_through_dm_call_signal() {
        let updated = method_source("dm_call_updated");

        assert!(
            updated.contains("self.dm_call_signal(DmCallSignal"),
            "dm_call_updated must hand its signal to dm_call_signal"
        );
        assert!(
            !updated.contains(".basic_publish("),
            "dm_call_updated must not publish on its own"
        );
    }
}
