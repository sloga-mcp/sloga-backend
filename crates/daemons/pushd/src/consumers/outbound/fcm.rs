use std::{collections::HashMap, sync::Arc, time::Duration};

use crate::utils::{call_push_ttl, CallPushTtl, Consumer};
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
///
/// `ttl_secs` is how long FCM may hold the message for a phone it cannot
/// reach right now. `None` sets nothing, so FCM keeps its own default: that
/// is what every push other than a call gets, as before.
fn android_config(ttl_secs: Option<u32>) -> Option<AndroidConfig> {
    Some(AndroidConfig {
        priority: Some(AndroidMessagePriority::High),
        // FCM wants a number of seconds followed by `s`
        ttl: ttl_secs.map(|secs| format!("{secs}s")),
        ..Default::default()
    })
}
use lapin::{message::Delivery, Channel as AMQPChannel, Connection};
use log::info;
use revolt_config::{config, effective_call_ring_secs};
use revolt_database::{events::rabbit::*, Database};
use serde_json::Value;

/// How long a call rings, in seconds, as every service and every app counts it.
async fn ring_secs() -> usize {
    effective_call_ring_secs(config().await.api.livekit.call_ring_duration)
}

/// How long a call push may live, or that it must not be sent at all.
/// `None` for every other kind of push: those have no lifetime of their own.
///
/// A ring that reaches a phone after the caller gave up makes it ring for
/// nobody, so a ring lives only for what is left of its ring time. Pure: the
/// clock and the ring length are handed in.
fn call_ttl(kind: &PayloadKind, now_unix: i64, ring_secs: usize) -> Option<CallPushTtl> {
    match kind {
        PayloadKind::DmCallStartEnd(alert) => Some(call_push_ttl(alert, now_unix, ring_secs)),
        _ => None,
    }
}

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
        call_id: Option<String>,
        reason: Option<String>,
        video: Option<bool>,
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
                call_id,
                reason,
                video,
            } => {
                // A call push names the caller and the conversation by id
                // only. It must never carry a display name, a photo link or
                // a group name: the app looks those up itself.
                data.insert("initiator_id".to_string(), Value::String(initiator_id));
                data.insert("channel_id".to_string(), Value::String(channel_id));
                data.insert("started_at".to_string(), Value::String(started_at));
                // FCM requires all data values to be strings (400 otherwise)
                data.insert("ended".to_string(), Value::String(ended.to_string()));
                data.insert("duration".to_string(), Value::String(duration.to_string()));

                // Each of these is sent only when the server set it, so a
                // push without them is exactly the push older apps know.
                if let Some(call_id) = call_id {
                    data.insert("call_id".to_string(), Value::String(call_id));
                }
                if let Some(reason) = reason {
                    data.insert("reason".to_string(), Value::String(reason));
                }
                if let Some(video) = video {
                    data.insert("video".to_string(), Value::String(video.to_string()));
                }
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
            duration: ring_secs().await,
            call_id: alert.call_id,
            reason: alert.reason,
            video: alert.video,
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

        let ring_secs = ring_secs().await;
        let ttl_secs = match call_ttl(&payload.notification, crate::utils::now_unix(), ring_secs) {
            Some(CallPushTtl::Drop) => {
                // This ring is already over: the push sat in a queue for
                // longer than the call rang. Sending it now would make a
                // phone ring for a call nobody is waiting on.
                info!("Not sending an FCM call push: its ring time is already over");
                return Ok(());
            }
            Some(CallPushTtl::Secs(secs)) => Some(secs),
            None => None,
        };

        let Some(data) = notification_data(payload.notification).await? else {
            bail!("FCM cannot handle badge updates and they should not be sent here.");
        };

        let msg = Message {
            token: Some(payload.token),
            data: Some(data.into_payload()),
            android: android_config(ttl_secs),
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

    /// A ring's `started_at` exactly as the voice service writes it.
    const RING_STARTED_AT: &str = "2026-09-23T00:00:00.000Z";
    /// The same moment in unix seconds.
    const RING_STARTED_UNIX: i64 = 1_790_121_600;

    /// Every key a call push may carry. `type` plus the five keys it has
    /// always had, plus the three a newer server may add. A call push names
    /// people and conversations by id only, so nothing else belongs here.
    const CALL_KEYS: [&str; 9] = [
        "type",
        "initiator_id",
        "channel_id",
        "started_at",
        "ended",
        "duration",
        "call_id",
        "reason",
        "video",
    ];

    fn ring() -> DmCallPayload {
        DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: Some(RING_STARTED_AT.to_string()),
            ended: false,
            ..Default::default()
        }
    }

    fn ended() -> DmCallPayload {
        DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: None,
            ended: true,
            ..Default::default()
        }
    }

    async fn call_map(payload: DmCallPayload) -> HashMap<String, Value> {
        notification_data(PayloadKind::DmCallStartEnd(payload))
            .await
            .expect("mapping a call push cannot fail")
            .expect("FCM sends call pushes")
            .into_payload()
    }

    /// This file's code without its tests, with all whitespace removed so a
    /// reformat cannot break a pin.
    fn shipping_source() -> String {
        let source = include_str!("fcm.rs");
        let end = source.find("#[cfg(test)]").expect("the test module marker");

        source[..end].split_whitespace().collect()
    }

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
                ..Default::default()
            }),
            PayloadKind::DmCallStartEnd(DmCallPayload {
                initiator_id: "01USER".to_string(),
                channel_id: "01CHANNEL".to_string(),
                started_at: None,
                ended: true,
                ..Default::default()
            }),
            PayloadKind::DmCallStartEnd(DmCallPayload {
                initiator_id: "01USER".to_string(),
                channel_id: "01CHANNEL".to_string(),
                started_at: Some(RING_STARTED_AT.to_string()),
                ended: false,
                call_id: Some("01CALL".to_string()),
                reason: None,
                video: Some(true),
            }),
            PayloadKind::DmCallStartEnd(DmCallPayload {
                initiator_id: "01USER".to_string(),
                channel_id: "01CHANNEL".to_string(),
                started_at: None,
                ended: true,
                call_id: Some("01CALL".to_string()),
                reason: Some(CALL_REASON_DECLINED.to_string()),
                video: None,
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
    /// `None` = the arm bailed before sending anything. The call arm is the
    /// exception and says why.
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

            // The one arm that is no longer the copy from before the
            // extraction, on purpose. A call push now also carries the ring's
            // id, why the ringing stopped and whether it is a video call, each
            // only when the server sent it, and `duration` is the ring length
            // every service agrees on rather than the raw setting. The map is
            // written out by hand so this expectation shares no code with the
            // mapping it checks.
            PayloadKind::DmCallStartEnd(alert) => {
                let ring_secs =
                    effective_call_ring_secs(config().await.api.livekit.call_ring_duration);

                let mut data = HashMap::new();
                let mut put = |key: &str, value: String| {
                    data.insert(key.to_string(), Value::String(value));
                };

                put("type", "push.dm.call".to_string());
                put("initiator_id", alert.initiator_id);
                put("channel_id", alert.channel_id);
                put("started_at", alert.started_at.unwrap_or_default());
                put("ended", alert.ended.to_string());
                put("duration", ring_secs.to_string());
                if let Some(call_id) = alert.call_id {
                    put("call_id", call_id);
                }
                if let Some(reason) = alert.reason {
                    put("reason", reason);
                }
                if let Some(video) = alert.video {
                    put("video", video.to_string());
                }

                Some(data)
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

    /// A payload that sets none of the newer fields is, key for key, the push
    /// apps already in the field know: nothing is added to it.
    ///
    /// `duration` used to be compared with the raw `call_ring_duration`
    /// setting. It is now the ring length every service agrees on, which is
    /// the same number for a sensible setting and differs only where the
    /// setting is zero or out of range.
    #[tokio::test]
    async fn dm_call_payload_is_all_strings() -> Result<()> {
        let data = notification_data(PayloadKind::DmCallStartEnd(DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: None,
            ended: true,
            ..Default::default()
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
                effective_call_ring_secs(config().await.api.livekit.call_ring_duration).to_string(),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), Value::String(v)))
        .collect();

        assert_eq!(data.into_payload(), expected);
        Ok(())
    }

    /// The setting is read in one place only, and that place puts it through
    /// the shared rule. The default setting cannot tell the raw value from
    /// the shared one (both are 45), so the source is pinned instead.
    #[test]
    fn ring_length_is_read_through_the_shared_rule() {
        let source = shipping_source();

        assert_eq!(
            source.matches("call_ring_duration").count(),
            1,
            "the ring length setting is read once, in `ring_secs`"
        );
        assert!(
            source.contains(
                "effective_call_ring_secs(config().await.api.livekit.call_ring_duration)"
            ),
            "the ring length must go through the shared rule"
        );
        assert!(
            source.contains("duration:ring_secs().await,"),
            "`duration` must be the shared ring length"
        );
    }

    #[tokio::test]
    async fn call_id_is_sent_only_when_the_payload_has_one() {
        let with = call_map(DmCallPayload {
            call_id: Some("01CALL".to_string()),
            ..ring()
        })
        .await;
        assert_eq!(
            with.get("call_id"),
            Some(&Value::String("01CALL".to_string()))
        );

        assert!(!call_map(ring()).await.contains_key("call_id"));
        assert!(!call_map(ended()).await.contains_key("call_id"));
    }

    #[tokio::test]
    async fn reason_is_sent_only_when_the_payload_has_one() {
        let with = call_map(DmCallPayload {
            reason: Some(CALL_REASON_ANSWERED_ELSEWHERE.to_string()),
            ..ended()
        })
        .await;
        assert_eq!(
            with.get("reason"),
            Some(&Value::String("answered_elsewhere".to_string()))
        );

        assert!(!call_map(ended()).await.contains_key("reason"));
        assert!(!call_map(ring()).await.contains_key("reason"));
    }

    /// `video` travels as the string "true" or "false": FCM refuses a data
    /// value that is not a string.
    #[tokio::test]
    async fn video_is_sent_as_a_string_only_when_the_payload_has_it() {
        for (video, expected) in [(true, "true"), (false, "false")] {
            let with = call_map(DmCallPayload {
                video: Some(video),
                ..ring()
            })
            .await;
            assert_eq!(
                with.get("video"),
                Some(&Value::String(expected.to_string())),
                "video = {video}"
            );
        }

        assert!(!call_map(ring()).await.contains_key("video"));
        assert!(!call_map(ended()).await.contains_key("video"));
    }

    /// A call push must never carry a name, a photo link or a group name, so
    /// the whole key set is pinned: a new key fails here until it is added to
    /// `CALL_KEYS` on purpose.
    #[tokio::test]
    async fn call_payload_has_no_key_outside_the_pinned_set() {
        let full_ring = DmCallPayload {
            call_id: Some("01CALL".to_string()),
            reason: Some(CALL_REASON_CANCELLED.to_string()),
            video: Some(true),
            ..ring()
        };
        let full_ended = DmCallPayload {
            call_id: Some("01CALL".to_string()),
            reason: Some(CALL_REASON_ENDED.to_string()),
            video: Some(false),
            ..ended()
        };

        // With every field set, the push carries the pinned set exactly.
        let pinned: HashSet<&str> = CALL_KEYS.into_iter().collect();
        for payload in [full_ring.clone(), full_ended.clone()] {
            let map = call_map(payload).await;
            let keys: HashSet<&str> = map.keys().map(String::as_str).collect();
            assert_eq!(keys, pinned);
        }

        // With any other mix of fields, it carries a part of it, all strings.
        let mut checked = 0;
        for payload in [ring(), ended(), full_ring, full_ended]
            .into_iter()
            .map(PayloadKind::DmCallStartEnd)
            .chain(samples())
        {
            let PayloadKind::DmCallStartEnd(payload) = payload else {
                continue;
            };

            for (key, value) in call_map(payload).await {
                assert!(CALL_KEYS.contains(&key.as_str()), "unexpected key {key}");
                assert!(value.is_string(), "{key} is not a string");
            }
            checked += 1;
        }
        assert_eq!(checked, 8, "four payloads here and four call samples");
    }

    /// Only a call has a lifetime of its own. Every other push keeps FCM's
    /// default, as it always has.
    #[test]
    fn only_a_call_push_gets_a_lifetime() {
        let mut others = 0;

        for kind in samples() {
            let ttl = call_ttl(&kind, RING_STARTED_UNIX, 45);

            if let PayloadKind::DmCallStartEnd(_) = kind {
                assert!(ttl.is_some(), "a call push always has a lifetime decision");
            } else {
                assert_eq!(ttl, None, "{}", variant(&kind));
                others += 1;
            }
        }

        assert_eq!(others, 10, "every sample that is not a call was checked");
    }

    /// A ring may wait for a phone only as long as the call is still ringing.
    #[test]
    fn a_ring_lives_for_what_is_left_of_its_ring_time() {
        let kind = PayloadKind::DmCallStartEnd(ring());

        assert_eq!(
            call_ttl(&kind, RING_STARTED_UNIX + 10, 45),
            Some(CallPushTtl::Secs(35))
        );
        assert_eq!(
            call_ttl(&kind, RING_STARTED_UNIX + 10, 30),
            Some(CallPushTtl::Secs(20))
        );
    }

    #[test]
    fn a_ring_that_is_already_over_is_to_be_dropped() {
        let kind = PayloadKind::DmCallStartEnd(ring());

        assert_eq!(
            call_ttl(&kind, RING_STARTED_UNIX + 300, 45),
            Some(CallPushTtl::Drop)
        );
    }

    /// The push that stops the ringing is worth delivering for a minute, no
    /// matter how long ago the ring started or how long a call rings.
    #[test]
    fn an_ended_push_lives_one_minute() {
        let kind = PayloadKind::DmCallStartEnd(ended());

        for ring_secs in [5, 45, 120] {
            assert_eq!(
                call_ttl(&kind, RING_STARTED_UNIX + 86_400, ring_secs),
                Some(CallPushTtl::Secs(60)),
                "ring_secs = {ring_secs}"
            );
        }
    }

    /// Nothing here can reach FCM, so what `consume` does with a ring that is
    /// over is pinned in its source: it returns before the payload is mapped
    /// or sent, logs once, and logs no user, session or token.
    #[test]
    fn a_ring_that_is_over_is_never_sent() {
        let source = shipping_source();
        let consume = &source[source.find("asyncfnconsume(").expect("consume")..];

        let decided = consume
            .find("call_ttl(&payload.notification,crate::utils::now_unix(),ring_secs")
            .expect("consume asks how long the push may live");
        let dropped = consume
            .find("Some(CallPushTtl::Drop)=>{")
            .expect("consume handles a ring that is over");
        let kept = consume
            .find("Some(CallPushTtl::Secs(secs))=>Some(secs),")
            .expect("consume keeps the lifetime of a live call push");
        let mapped = consume
            .find("notification_data(payload.notification)")
            .expect("consume maps the payload");
        let sent = consume
            .find("self.client.send(")
            .expect("consume sends the message");

        assert!(decided < dropped && dropped < kept && kept < mapped && mapped < sent);

        let drop_arm = &consume[dropped..kept];
        assert!(
            drop_arm.ends_with("returnOk(());}"),
            "a ring that is over must end `consume` without an error: {drop_arm}"
        );
        assert_eq!(drop_arm.matches("info!(").count(), 1, "{drop_arm}");
        assert!(
            !drop_arm.contains("payload."),
            "the log line must not name a user, a session or a token: {drop_arm}"
        );

        assert!(
            consume.contains("android:android_config(ttl_secs),"),
            "the message must carry the lifetime that was decided"
        );
    }

    /// Every push other than a call is sent exactly as before: high priority
    /// and no lifetime of its own.
    #[test]
    fn a_push_without_a_lifetime_sets_no_ttl() {
        assert_eq!(
            serde_json::to_value(android_config(None)).expect("serializes"),
            json!({ "priority": "HIGH" })
        );
    }

    /// A call push stays high priority, or a dozing phone would get it late,
    /// and carries its lifetime in the form FCM accepts.
    #[test]
    fn a_call_push_is_high_priority_with_its_lifetime_in_seconds() {
        assert_eq!(
            serde_json::to_value(android_config(Some(35))).expect("serializes"),
            json!({ "priority": "HIGH", "ttl": "35s" })
        );
        assert_eq!(
            serde_json::to_value(android_config(Some(60))).expect("serializes"),
            json!({ "priority": "HIGH", "ttl": "60s" })
        );
    }
}
