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

/// Map an outbound payload to the data FCM carries for it.
///
/// `Ok(None)` means FCM does not send this kind (badge updates).
pub(crate) async fn notification_data(kind: PayloadKind) -> Result<Option<NotificationData>> {
    Ok(Some(match kind {
        PayloadKind::FRReceived(alert) => {
            let name = alert.from_user.display_name.clone().unwrap_or_else(|| {
                format!(
                    "{}#{}",
                    alert.from_user.username, alert.from_user.discriminator
                )
            });

            NotificationData::FRReceived {
                id: alert.from_user.id,
                username: name,
            }
        }

        PayloadKind::FRAccepted(alert) => {
            let name = alert.accepted_user.display_name.clone().unwrap_or_else(|| {
                format!(
                    "{}#{}",
                    alert.accepted_user.username, alert.accepted_user.discriminator
                )
            });

            NotificationData::FRAccepted {
                id: alert.accepted_user.id,
                username: name,
            }
        }

        PayloadKind::Generic(alert) => NotificationData::Generic {
            title: alert.title,
            body: alert.body,
            image: alert.icon,
        },

        PayloadKind::MessageNotification(alert) => NotificationData::Message {
            message: alert.message.id,
            body: alert.body,
            image: alert.icon,
            channel: alert.message.channel,
            author: alert.message.author,
            author_name: alert.author,
        },

        PayloadKind::DmCallStartEnd(alert) => NotificationData::DmCallStartEnd {
            initiator_id: alert.initiator_id,
            channel_id: alert.channel_id,
            started_at: alert.started_at.unwrap_or_else(|| "".to_string()),
            ended: alert.ended,
            duration: config().await.api.livekit.call_ring_duration,
        },

        PayloadKind::CalendarEvent(alert) => NotificationData::CalendarEvent {
            event_id: alert.event_id,
            server_id: alert.server_id,
            title: alert.title,
            kind: alert.kind.as_str().to_string(),
            occurrence_start: alert.occurrence_start,
            channel_id: alert.channel_id,
            offset_ms: alert.offset_ms,
        },

        PayloadKind::BadgeUpdate(_) => return Ok(None),
    }))
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

        let Some(data) = notification_data(payload.notification).await? else {
            bail!("FCM cannot handle badge updates and they should not be sent here.");
        };

        let msg = Message {
            token: Some(payload.token),
            data: Some(data.into_payload()),
            android: high_priority(),
            ..Default::default()
        };

        let resp: Result<Message, FcmError> = self.client.send(&msg).await;

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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use revolt_database::User;
    use revolt_models::v0::{Channel, PushNotification};
    use serde_json::json;

    fn user(display_name: Option<&str>) -> User {
        User {
            id: "01USER".to_string(),
            username: "alice".to_string(),
            discriminator: "1234".to_string(),
            display_name: display_name.map(str::to_string),
            ..Default::default()
        }
    }

    /// One payload per `PayloadKind` variant, plus each optional branch of the
    /// mapping. Built fresh per call because `PayloadKind` is not `Clone`.
    fn samples() -> Vec<PayloadKind> {
        vec![
            PayloadKind::FRReceived(FRReceivedPayload {
                from_user: user(None),
                user: "01RECIPIENT".to_string(),
            }),
            PayloadKind::FRReceived(FRReceivedPayload {
                from_user: user(Some("Alice")),
                user: "01RECIPIENT".to_string(),
            }),
            PayloadKind::FRAccepted(FRAcceptedPayload {
                accepted_user: user(None),
                user: "01RECIPIENT".to_string(),
            }),
            PayloadKind::FRAccepted(FRAcceptedPayload {
                accepted_user: user(Some("Alice")),
                user: "01RECIPIENT".to_string(),
            }),
            PayloadKind::Generic(GenericPayload {
                title: "Title".to_string(),
                body: "Body".to_string(),
                icon: Some("https://example.com/icon.png".to_string()),
                user: user(None),
            }),
            PayloadKind::Generic(GenericPayload {
                title: "Title".to_string(),
                body: "Body".to_string(),
                icon: None,
                user: user(None),
            }),
            PayloadKind::MessageNotification(PushNotification {
                author: "Alice".to_string(),
                icon: "https://example.com/avatar.png".to_string(),
                image: Some("https://example.com/attachment.png".to_string()),
                body: "hello".to_string(),
                raw_body: None,
                tag: "01CHANNEL".to_string(),
                timestamp: 1_700_000_000_000,
                url: "https://example.com/channel/01CHANNEL/01MESSAGE".to_string(),
                message: serde_json::from_value(json!({
                    "_id": "01MESSAGE",
                    "channel": "01CHANNEL",
                    "author": "01USER",
                }))
                .expect("minimal message"),
                channel: Channel::SavedMessages {
                    id: "01CHANNEL".to_string(),
                    user: "01USER".to_string(),
                },
            }),
            PayloadKind::DmCallStartEnd(DmCallPayload {
                initiator_id: "01USER".to_string(),
                channel_id: "01CHANNEL".to_string(),
                started_at: Some("2026-09-23T00:00:00.000Z".to_string()),
                ended: false,
            }),
            PayloadKind::DmCallStartEnd(DmCallPayload {
                initiator_id: "01USER".to_string(),
                channel_id: "01CHANNEL".to_string(),
                started_at: None,
                ended: true,
            }),
            PayloadKind::CalendarEvent(CalendarEventPayload {
                user: "01RECIPIENT".to_string(),
                event_id: "01EVENT".to_string(),
                server_id: "01SERVER".to_string(),
                title: "Raid night".to_string(),
                kind: CalendarEventNotification::Reminder,
                occurrence_start: Some(1_700_000_000_000),
                channel_id: Some("01CHANNEL".to_string()),
                offset_ms: Some(0),
            }),
            PayloadKind::CalendarEvent(CalendarEventPayload {
                user: "01RECIPIENT".to_string(),
                event_id: "01EVENT".to_string(),
                server_id: "01SERVER".to_string(),
                title: "Raid night".to_string(),
                kind: CalendarEventNotification::Invited,
                occurrence_start: None,
                channel_id: None,
                offset_ms: None,
            }),
            PayloadKind::BadgeUpdate(3),
        ]
    }

    /// Exhaustive on purpose: a new `PayloadKind` variant fails to compile here
    /// until it is given a sample and a golden expectation.
    fn variant(kind: &PayloadKind) -> &'static str {
        match kind {
            PayloadKind::MessageNotification(_) => "MessageNotification",
            PayloadKind::FRAccepted(_) => "FRAccepted",
            PayloadKind::FRReceived(_) => "FRReceived",
            PayloadKind::BadgeUpdate(_) => "BadgeUpdate",
            PayloadKind::Generic(_) => "Generic",
            PayloadKind::DmCallStartEnd(_) => "DmCallStartEnd",
            PayloadKind::CalendarEvent(_) => "CalendarEvent",
        }
    }

    /// Verbatim copy of the mapping arms `consume()` had before the extraction,
    /// with each `Message` build + send replaced by returning the data map.
    /// `None` = the arm bailed before sending anything.
    async fn legacy_expected(notification: PayloadKind) -> Option<HashMap<String, Value>> {
        match notification {
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

                Some(data.into_payload())
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

                Some(data.into_payload())
            }
            PayloadKind::Generic(alert) => {
                let data = NotificationData::Generic {
                    title: alert.title,
                    body: alert.body,
                    image: alert.icon,
                };

                Some(data.into_payload())
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

                Some(data.into_payload())
            }

            PayloadKind::DmCallStartEnd(alert) => {
                let data = NotificationData::DmCallStartEnd {
                    initiator_id: alert.initiator_id,
                    channel_id: alert.channel_id,
                    started_at: alert.started_at.unwrap_or_else(|| "".to_string()),
                    ended: alert.ended,
                    duration: config().await.api.livekit.call_ring_duration,
                };

                Some(data.into_payload())
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

                Some(data.into_payload())
            }

            PayloadKind::BadgeUpdate(_) => None,
        }
    }

    #[tokio::test]
    async fn notification_data_matches_legacy_mapping() -> Result<()> {
        let mut seen = HashSet::new();

        for (kind, legacy) in samples().into_iter().zip(samples()) {
            let name = variant(&kind);
            seen.insert(name);

            let actual = notification_data(kind).await?.map(|d| d.into_payload());
            assert_eq!(actual, legacy_expected(legacy).await, "{name}");
        }

        assert_eq!(seen.len(), 7, "every PayloadKind variant has a sample");
        Ok(())
    }

    #[tokio::test]
    async fn dm_call_payload_is_all_strings() -> Result<()> {
        let data = notification_data(PayloadKind::DmCallStartEnd(DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: None,
            ended: true,
        }))
        .await?
        .expect("FCM sends call pushes");

        let expected: HashMap<String, Value> = [
            ("type", "push.dm.call".to_string()),
            ("initiator_id", "01USER".to_string()),
            ("channel_id", "01CHANNEL".to_string()),
            ("started_at", "".to_string()),
            ("ended", "true".to_string()),
            (
                "duration",
                config().await.api.livekit.call_ring_duration.to_string(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Value::String(v)))
        .collect();

        assert_eq!(data.into_payload(), expected);
        Ok(())
    }
}
