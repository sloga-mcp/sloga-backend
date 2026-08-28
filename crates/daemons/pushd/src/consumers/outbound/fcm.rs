use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::utils::Consumer;
use anyhow::{bail, Result};
use async_trait::async_trait;
use fcm_v1::{
    android::{AndroidConfig, AndroidMessagePriority},
    auth::{Authenticator, ServiceAccountKey},
    message::Message,
    Client, Error as FcmError,
};

/// Data-only messages are delivered lazily on dozing devices unless sent at
/// high priority — which makes notifications arrive minutes late.
fn high_priority() -> Option<AndroidConfig> {
    Some(AndroidConfig {
        priority: Some(AndroidMessagePriority::High),
        ..Default::default()
    })
}
use lapin::{message::Delivery, Channel as AMQPChannel, Connection};
use log::info;
use revolt_config::config;
use revolt_database::{events::rabbit::*, Database};
use serde_json::Value;

/// Custom notification data
#[derive(Debug, Clone, PartialEq)]
pub enum NotificationData {
    FRReceived {
        id: String,
        username: String,
    },
    FRAccepted {
        id: String,
        username: String,
    },
    Generic {
        title: String,
        body: String,
        image: Option<String>,
    },
    Message {
        message: String,
        body: String,
        image: String,
        channel: String,
        author: String,
        author_name: String,
    },
    DmCallStartEnd {
        initiator_id: String,
        channel_id: String,
        started_at: String,
        ended: bool,
        duration: usize,
    },
    CalendarEvent {
        event_id: String,
        server_id: String,
        title: String,
        kind: String,
        occurrence_start: Option<i64>,
        channel_id: Option<String>,
        offset_ms: Option<i64>,
    },
}

impl NotificationData {
    pub fn get_type(&self) -> &str {
        match self {
            NotificationData::FRReceived { .. } => "push.fr.receive",
            NotificationData::FRAccepted { .. } => "push.fr.accept",
            NotificationData::Generic { .. } => "push.generic",
            NotificationData::Message { .. } => "push.message",
            NotificationData::DmCallStartEnd { .. } => "push.dm.call",
            NotificationData::CalendarEvent { .. } => "push.calendar",
        }
    }

    pub fn into_payload(self) -> HashMap<String, Value> {
        let mut data = HashMap::new();
        data.insert(
            "type".to_string(),
            Value::String(self.get_type().to_string()),
        );

        match self {
            NotificationData::FRReceived { id, username } => {
                data.insert("id".to_string(), Value::String(id));
                data.insert("username".to_string(), Value::String(username));
            }
            NotificationData::FRAccepted { id, username } => {
                data.insert("id".to_string(), Value::String(id));
                data.insert("username".to_string(), Value::String(username));
            }
            NotificationData::Generic { title, body, image } => {
                data.insert("title".to_string(), Value::String(title));
                data.insert("body".to_string(), Value::String(body));

                if let Some(image) = image {
                    data.insert("image".to_string(), Value::String(image));
                }
            }
            NotificationData::Message {
                message,
                body,
                image,
                channel,
                author,
                author_name,
            } => {
                data.insert("message".to_string(), Value::String(message));
                data.insert("body".to_string(), Value::String(body));
                data.insert("image".to_string(), Value::String(image));
                data.insert("channel".to_string(), Value::String(channel));
                data.insert("author".to_string(), Value::String(author));
                data.insert("author_name".to_string(), Value::String(author_name));
            }
            NotificationData::DmCallStartEnd {
                initiator_id,
                channel_id,
                started_at,
                ended,
                duration,
            } => {
                data.insert("initiator_id".to_string(), Value::String(initiator_id));
                data.insert("channel_id".to_string(), Value::String(channel_id));
                data.insert("started_at".to_string(), Value::String(started_at));
                // FCM requires all data values to be strings (400 otherwise)
                data.insert("ended".to_string(), Value::String(ended.to_string()));
                data.insert("duration".to_string(), Value::String(duration.to_string()));
            }
            NotificationData::CalendarEvent {
                event_id,
                server_id,
                title,
                kind,
                occurrence_start,
                channel_id,
                offset_ms,
            } => {
                data.insert("event_id".to_string(), Value::String(event_id));
                data.insert("server_id".to_string(), Value::String(server_id));
                data.insert("title".to_string(), Value::String(title));
                data.insert("kind".to_string(), Value::String(kind));
                // FCM requires all data values to be strings (400 otherwise)
                if let Some(occurrence_start) = occurrence_start {
                    data.insert(
                        "occurrence_start".to_string(),
                        Value::String(occurrence_start.to_string()),
                    );
                }
                if let Some(channel_id) = channel_id {
                    data.insert("channel_id".to_string(), Value::String(channel_id));
                }
                if let Some(offset_ms) = offset_ms {
                    data.insert(
                        "offset_ms".to_string(),
                        Value::String(offset_ms.to_string()),
                    );
                }
            }
        }

        data
    }
}

#[derive(Clone)]
#[allow(unused)]
pub struct FcmOutboundConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<AMQPChannel>,
    client: Client,
}

#[async_trait]
impl Consumer for FcmOutboundConsumer {
    async fn create(db: Database, connection: Arc<Connection>, channel: Arc<AMQPChannel>) -> Self {
        let config = revolt_config::config().await;

        Self {
            db,
            connection,
            channel,
            client: Client::new(
                Authenticator::service_account::<&str>(ServiceAccountKey {
                    key_type: Some(config.pushd.fcm.key_type),
                    project_id: Some(config.pushd.fcm.project_id.clone()),
                    private_key_id: Some(config.pushd.fcm.private_key_id),
                    private_key: config.pushd.fcm.private_key,
                    client_email: config.pushd.fcm.client_email,
                    client_id: Some(config.pushd.fcm.client_id),
                    auth_uri: Some(config.pushd.fcm.auth_uri),
                    token_uri: config.pushd.fcm.token_uri,
                    auth_provider_x509_cert_url: Some(config.pushd.fcm.auth_provider_x509_cert_url),
                    client_x509_cert_url: Some(config.pushd.fcm.client_x509_cert_url),
                })
                .await
                .unwrap(),
                config.pushd.fcm.project_id,
                false,
                Duration::from_secs(5),
            ),
        }
    }

    fn channel(&self) -> &Arc<AMQPChannel> {
        &self.channel
    }

    async fn consume(&self, delivery: Delivery) -> Result<()> {
        let payload: PayloadToService = serde_json::from_slice(&delivery.data)?;

        #[allow(clippy::needless_late_init)]
        let resp: Result<Message, FcmError>;

        match payload.notification {
            PayloadKind::FRReceived(alert) => {
                let name = alert.from_user.display_name.clone().unwrap_or_else(|| {
                    format!(
                        "{}#{}",
                        alert.from_user.username, alert.from_user.discriminator
                    )
                });

                let data = NotificationData::FRReceived {
                    id: alert.from_user.id,
                    username: name,
                };

                let msg = Message {
                    token: Some(payload.token),
                    data: Some(data.into_payload()),
                    android: high_priority(),
                    ..Default::default()
                };

                resp = self.client.send(&msg).await;
            }

            PayloadKind::FRAccepted(alert) => {
                let name = alert.accepted_user.display_name.clone().unwrap_or_else(|| {
                    format!(
                        "{}#{}",
                        alert.accepted_user.username, alert.accepted_user.discriminator
                    )
                });

                let data = NotificationData::FRAccepted {
                    id: alert.accepted_user.id,
                    username: name,
                };

                let msg = Message {
                    token: Some(payload.token),
                    data: Some(data.into_payload()),
                    android: high_priority(),
                    ..Default::default()
                };

                resp = self.client.send(&msg).await;
            }
            PayloadKind::Generic(alert) => {
                let data = NotificationData::Generic {
                    title: alert.title,
                    body: alert.body,
                    image: alert.icon,
                };

                let msg = Message {
                    token: Some(payload.token),
                    data: Some(data.into_payload()),
                    android: high_priority(),
                    ..Default::default()
                };

                resp = self.client.send(&msg).await;
            }

            PayloadKind::MessageNotification(alert) => {
                let data = NotificationData::Message {
                    message: alert.message.id,
                    body: alert.body,
                    image: alert.icon,
                    channel: alert.message.channel,
                    author: alert.message.author,
                    author_name: alert.author,
                };

                let msg = Message {
                    token: Some(payload.token),
                    data: Some(data.into_payload()),
                    android: high_priority(),
                    ..Default::default()
                };

                resp = self.client.send(&msg).await;
            }

            PayloadKind::DmCallStartEnd(alert) => {
                let data = NotificationData::DmCallStartEnd {
                    initiator_id: alert.initiator_id,
                    channel_id: alert.channel_id,
                    started_at: alert.started_at.unwrap_or_else(|| "".to_string()),
                    ended: alert.ended,
                    duration: config().await.api.livekit.call_ring_duration,
                };

                let msg = Message {
                    token: Some(payload.token),
                    data: Some(data.into_payload()),
                    android: high_priority(),
                    ..Default::default()
                };

                resp = self.client.send(&msg).await;
            }

            PayloadKind::CalendarEvent(alert) => {
                let data = NotificationData::CalendarEvent {
                    event_id: alert.event_id,
                    server_id: alert.server_id,
                    title: alert.title,
                    kind: alert.kind.as_str().to_string(),
                    occurrence_start: alert.occurrence_start,
                    channel_id: alert.channel_id,
                    offset_ms: alert.offset_ms,
                };

                let msg = Message {
                    token: Some(payload.token),
                    data: Some(data.into_payload()),
                    android: high_priority(),
                    ..Default::default()
                };

                resp = self.client.send(&msg).await;
            }

            PayloadKind::BadgeUpdate(_) => {
                bail!("FCM cannot handle badge updates and they should not be sent here.");
            }
        }

        match resp {
            Err(FcmError::Auth) => {
                // fcm_v1 maps any failure to mint OUR service-account OAuth
                // token to Error::Auth — it says nothing about the device
                // token, so the subscription must survive it. Removing it here
                // silently killed push (messages AND call rings) for healthy
                // sessions whenever Google auth blipped.
                bail!("FCM service-account authentication failed (subscription kept)");
            }
            // A dead registration token (app uninstalled, data cleared, token
            // rotated away) is permanent: FCM answers 404 UNREGISTERED. Drop
            // the subscription so every future notification isn't burned on it.
            Err(FcmError::FCM(ref msg)) if msg.contains("UNREGISTERED") => {
                info!(
                    "Removing FCM subscription id {:} (user: {:}) due to unregistered token",
                    &payload.session_id, &payload.user_id
                );

                if let Err(err) = self
                    .db
                    .remove_push_subscription_by_session_id(&payload.session_id)
                    .await
                {
                    revolt_config::capture_error(&err);
                }
            }
            res => {
                res?;
            }
        };

        Ok(())
    }
}
