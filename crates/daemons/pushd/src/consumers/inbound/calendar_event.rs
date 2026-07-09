use std::{collections::HashMap, sync::Arc};

use crate::utils::Consumer;
use anyhow::Result;
use async_trait::async_trait;
use lapin::{message::Delivery, Channel, Connection};
use log::debug;
use revolt_database::{events::rabbit::*, Database};

#[derive(Clone)]
#[allow(unused)]
pub struct CalendarEventConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<Channel>,
}

#[async_trait]
impl Consumer for CalendarEventConsumer {
    async fn create(db: Database, connection: Arc<Connection>, channel: Arc<Channel>) -> Self {
        Self {
            db,
            connection,
            channel,
        }
    }

    fn channel(&self) -> &Arc<Channel> {
        &self.channel
    }

    /// Fan a single calendar-event notification out to the recipient's subscribed
    /// sessions. The recipient is addressed by user id only (never by channel
    /// membership) so a `Going` attendee who has since lost `ViewChannel` is still
    /// reached for cancels/reminders (design §8/§9).
    async fn consume(&self, delivery: Delivery) -> Result<()> {
        let payload: CalendarEventPayload = serde_json::from_slice(&delivery.data)?;

        debug!("Received calendar event notification on origin");

        if let Ok(sessions) = self
            .db
            .fetch_sessions_with_subscription(&[payload.user.clone()])
            .await
        {
            let config = revolt_config::config().await;
            for session in sessions {
                if let Some(sub) = session.subscription {
                    let mut sendable = PayloadToService {
                        notification: PayloadKind::CalendarEvent(payload.clone()),
                        token: sub.auth,
                        user_id: session.user_id,
                        session_id: session.id,
                        extras: HashMap::new(),
                    };

                    let routing_key = match sub.endpoint.as_str() {
                        "apn" => &config.pushd.apn.queue,
                        "fcm" => &config.pushd.fcm.queue,
                        endpoint => {
                            sendable.extras.insert("p256dh".to_string(), sub.p256dh);
                            sendable
                                .extras
                                .insert("endpoint".to_string(), endpoint.to_string());

                            &config.pushd.vapid.queue
                        }
                    };

                    let payload = serde_json::to_string(&sendable)?;

                    self.publish_message(payload.as_bytes(), &config.pushd.exchange, routing_key)
                        .await?;
                }
            }
        }

        Ok(())
    }
}
