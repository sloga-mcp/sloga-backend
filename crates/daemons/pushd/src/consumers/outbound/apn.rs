use std::{borrow::Cow, collections::BTreeMap, io::Cursor, sync::Arc};

use crate::utils::{is_protected, Consumer, PROTECTED_PUSH_TITLE};
use anyhow::Result;
use async_trait::async_trait;
use base64::{
    engine::{self},
    Engine as _,
};
use lapin::{message::Delivery, Channel as AMQPChannel, Connection};
use revolt_a2::{
    request::{
        notification::{DefaultAlert, NotificationOptions},
        payload::{APSAlert, APSSound, Payload, PayloadLike, APS},
    },
    Client, ClientConfig, Endpoint, Error, ErrorBody, ErrorReason, Priority, PushType, Response,
};
use revolt_database::{events::rabbit::*, Database};
use revolt_models::v0::{Channel, Message, PushNotification, PROTECTED_PUSH_BODY};
use serde::Serialize;

// region: payload

#[derive(Serialize, Debug)]
struct MessagePayload<'a> {
    aps: APS<'a>,
    #[serde(skip_serializing)]
    options: NotificationOptions<'a>,
    #[serde(skip_serializing)]
    device_token: &'a str,

    message: &'a Message,
    url: &'a str,
    #[serde(rename = "camelCase")]
    author_avatar: &'a str,
    #[serde(rename = "camelCase")]
    author_display_name: &'a str,
    #[serde(rename = "camelCase")]
    channel_name: &'a str,
}

impl<'a> PayloadLike for MessagePayload<'a> {
    fn get_device_token(&self) -> &'a str {
        self.device_token
    }
    fn get_options(&self) -> &NotificationOptions<'a> {
        &self.options
    }
}

/// A protected-channel message (S8-O4): the generic alert, the channel as
/// the thread, and the url that opens the message. No author, avatar,
/// channel name or message object
#[derive(Serialize, Debug)]
struct ProtectedMessagePayload<'a> {
    aps: APS<'a>,
    #[serde(skip_serializing)]
    options: NotificationOptions<'a>,
    #[serde(skip_serializing)]
    device_token: &'a str,

    url: &'a str,
}

impl<'a> PayloadLike for ProtectedMessagePayload<'a> {
    fn get_device_token(&self) -> &'a str {
        self.device_token
    }
    fn get_options(&self) -> &NotificationOptions<'a> {
        &self.options
    }
}

#[derive(Debug)]
enum MessageAlert<'a> {
    Plain(MessagePayload<'a>),
    Protected(ProtectedMessagePayload<'a>),
}

/// The payload of a message notification. `title` is `format_title`'s and
/// is used only for an unprotected message
fn message_payload<'a>(
    alert: &'a PushNotification,
    title: &'a str,
    badge: Option<u32>,
    device_token: &'a str,
    options: NotificationOptions<'a>,
) -> MessageAlert<'a> {
    if is_protected(alert) {
        return MessageAlert::Protected(ProtectedMessagePayload {
            aps: APS {
                alert: Some(APSAlert::Default(DefaultAlert {
                    title: Some(PROTECTED_PUSH_TITLE),
                    subtitle: None,
                    body: Some(PROTECTED_PUSH_BODY),
                    title_loc_key: None,
                    title_loc_args: None,
                    action_loc_key: None,
                    loc_key: None,
                    loc_args: None,
                    launch_image: None,
                })),
                badge,
                sound: Some(APSSound::Sound("default")),
                thread_id: Some(alert.channel.id()),
                content_available: None,
                category: None,
                mutable_content: Some(1),
                url_args: None,
            },
            device_token,
            options,
            url: &alert.url,
        });
    }

    MessageAlert::Plain(MessagePayload {
        aps: APS {
            alert: Some(APSAlert::Default(DefaultAlert {
                title: Some(title),
                subtitle: None,
                body: Some(&alert.body),
                title_loc_key: None,
                title_loc_args: None,
                action_loc_key: None,
                loc_key: None,
                loc_args: None,
                launch_image: None,
            })),
            badge,
            sound: Some(APSSound::Sound("default")),
            thread_id: Some(alert.channel.id()),
            content_available: None,
            category: None,
            mutable_content: Some(1),
            url_args: None,
        },
        device_token,
        options,
        message: &alert.message,
        url: &alert.url,
        author_avatar: &alert.icon,
        author_display_name: &alert.author,
        channel_name: alert.channel.name().unwrap_or(title),
    })
}

fn format_title(notification: &PushNotification) -> String {
    // ideally this changes depending on context
    // in a server, it would look like "Sendername, #channelname in servername"
    // in a group, it would look like "Sendername in groupname"
    // in a dm it should just be "Sendername".
    // not sure how feasible all those are given the PushNotification object as it currently stands.

    #[allow(deprecated)]
    match &notification.channel {
        Channel::DirectMessage { .. } => notification.author.clone(),
        Channel::Group { name, .. } => format!("{}, #{}", notification.author, name),
        Channel::TextChannel { name, .. }
        | Channel::Thread { name, .. }
        | Channel::Forum { name, .. } => {
            format!("{} in #{}", notification.author, name)
        }
        _ => "Unknown".to_string(),
    }
}

#[derive(Serialize, Debug)]
struct CallStartStopPayload<'a> {
    aps: APS<'a>,
    #[serde(skip_serializing)]
    options: NotificationOptions<'a>,
    #[serde(skip_serializing)]
    device_token: &'a str,

    initiator_id: &'a str,
    #[serde(rename = "camelCase")]
    channel_id: &'a str,
    #[serde(rename = "camelCase")]
    started_at: &'a str,
    #[serde(rename = "camelCase")]
    ended: bool,
}

impl<'a> PayloadLike for CallStartStopPayload<'a> {
    fn get_device_token(&self) -> &'a str {
        self.device_token
    }
    fn get_options(&self) -> &NotificationOptions<'a> {
        &self.options
    }
}

#[derive(Serialize, Debug)]
struct CalendarEventPayload<'a> {
    aps: APS<'a>,
    #[serde(skip_serializing)]
    options: NotificationOptions<'a>,
    #[serde(skip_serializing)]
    device_token: &'a str,

    // Structured fields for client deep-linking / kind discrimination (parity with the
    // FCM/VAPID arms; mirrors how CallStartStopPayload carries call ids). Keys match the
    // FCM data payload so clients route uniformly across platforms.
    event_id: &'a str,
    server_id: &'a str,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrence_start: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offset_ms: Option<i64>,
}

impl<'a> PayloadLike for CalendarEventPayload<'a> {
    fn get_device_token(&self) -> &'a str {
        self.device_token
    }
    fn get_options(&self) -> &NotificationOptions<'a> {
        &self.options
    }
}

// region: consumer

#[derive(Clone)]
#[allow(unused)]
pub struct ApnsOutboundConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<AMQPChannel>,
    client: Client,
    /// Bundle identifier of the iOS app, read once at startup.
    topic: String,
}

impl ApnsOutboundConsumer {
    async fn get_badge_count(&self, user: &str) -> Option<u32> {
        if let Ok(unreads) = self.db.fetch_unread_mentions(user).await {
            let mut mention_count = 0;
            for channel in unreads {
                if let Some(mentions) = channel.mentions {
                    mention_count += mentions.len() as u32
                }
            }

            debug!("Got badge count for APN: {}", mention_count);

            return Some(mention_count);
        }
        None
    }
}

#[async_trait]
impl Consumer for ApnsOutboundConsumer {
    async fn create(db: Database, connection: Arc<Connection>, channel: Arc<AMQPChannel>) -> Self {
        let config = revolt_config::config().await;

        if config.pushd.apn.pkcs8.is_empty()
            || config.pushd.apn.key_id.is_empty()
            || config.pushd.apn.team_id.is_empty()
        {
            panic!("Missing APN keys.");
        }

        if config.pushd.apn.topic.is_empty() {
            panic!("Missing APN topic (must be the iOS bundle identifier).");
        }

        let endpoint = if config.pushd.apn.sandbox {
            Endpoint::Sandbox
        } else {
            Endpoint::Production
        };

        let pkcs8 = engine::general_purpose::STANDARD
            .decode(config.pushd.apn.pkcs8.clone())
            .expect("valid `pcks8`");

        let client_config = ClientConfig::new(endpoint);

        let client = Client::token(
            &mut Cursor::new(pkcs8),
            config.pushd.apn.key_id.clone(),
            config.pushd.apn.team_id.clone(),
            client_config,
        )
        .expect("could not create APN client");

        Self {
            db,
            connection,
            channel,
            client,
            topic: config.pushd.apn.topic.clone(),
        }
    }

    fn channel(&self) -> &Arc<AMQPChannel> {
        &self.channel
    }

    async fn consume(&self, delivery: Delivery) -> Result<()> {
        let payload: PayloadToService = serde_json::from_slice(&delivery.data)?;

        let payload_options = NotificationOptions {
            apns_id: None,
            apns_push_type: Some(PushType::Alert),
            apns_expiration: None,
            apns_priority: Some(Priority::High),
            apns_topic: Some(&self.topic),
            apns_collapse_id: None,
        };

        let resp = match payload.notification {
            PayloadKind::FRReceived(alert) => {
                let loc_args = vec![Cow::from(
                    alert.from_user.display_name.clone().unwrap_or_else(|| {
                        format!(
                            "{}#{}",
                            alert.from_user.username, alert.from_user.discriminator
                        )
                    }),
                )];

                let apn_payload = Payload {
                    aps: APS {
                        alert: Some(APSAlert::Default(DefaultAlert {
                            title: None,
                            subtitle: None,
                            body: None,
                            title_loc_key: None,
                            title_loc_args: None,
                            action_loc_key: None,
                            loc_key: Some("push.fr.received"),
                            loc_args: Some(loc_args),
                            launch_image: None,
                        })),
                        badge: self.get_badge_count(&payload.user_id).await,
                        sound: Some(APSSound::Sound("default")),
                        thread_id: None,
                        content_available: None,
                        category: None,
                        mutable_content: Some(1),
                        url_args: None,
                    },
                    device_token: &payload.token,
                    options: payload_options.clone(),
                    data: BTreeMap::new(),
                };

                debug!(
                    "Sending friend request received for user: {:}",
                    &payload.user_id
                );
                self.client.send(apn_payload).await
            }

            PayloadKind::FRAccepted(alert) => {
                let loc_args = vec![Cow::from(
                    alert.accepted_user.display_name.clone().unwrap_or_else(|| {
                        format!(
                            "{}#{}",
                            alert.accepted_user.username, alert.accepted_user.discriminator
                        )
                    }),
                )];

                let apn_payload = Payload {
                    aps: APS {
                        alert: Some(APSAlert::Default(DefaultAlert {
                            title: None,
                            subtitle: None,
                            body: None,
                            title_loc_key: None,
                            title_loc_args: None,
                            action_loc_key: None,
                            loc_key: Some("push.fr.accepted"),
                            loc_args: Some(loc_args),
                            launch_image: None,
                        })),
                        badge: self.get_badge_count(&payload.user_id).await,
                        sound: Some(APSSound::Sound("default")),
                        thread_id: None,
                        content_available: None,
                        category: None,
                        mutable_content: Some(1),
                        url_args: None,
                    },
                    device_token: &payload.token,
                    options: payload_options.clone(),
                    data: BTreeMap::new(),
                };

                debug!(
                    "Sending friend request accept for user: {:}",
                    &payload.user_id
                );
                self.client.send(apn_payload).await
            }
            PayloadKind::Generic(alert) => {
                let apn_payload = Payload {
                    aps: APS {
                        alert: Some(APSAlert::Default(DefaultAlert {
                            title: Some(&alert.title),
                            subtitle: None,
                            body: Some(&alert.body),
                            title_loc_key: None,
                            title_loc_args: None,
                            action_loc_key: None,
                            loc_key: None,
                            loc_args: None,
                            launch_image: None,
                        })),
                        badge: self.get_badge_count(&payload.user_id).await,
                        sound: Some(APSSound::Sound("default")),
                        thread_id: None,
                        content_available: None,
                        category: None,
                        mutable_content: Some(1),
                        url_args: None,
                    },
                    device_token: &payload.token,
                    options: payload_options.clone(),
                    data: BTreeMap::new(),
                };

                debug!(
                    "Sending generic notification for user: {:}",
                    &payload.user_id
                );
                self.client.send(apn_payload).await
            }

            PayloadKind::MessageNotification(alert) => {
                let title = format_title(&alert);
                let badge = self.get_badge_count(&payload.user_id).await;

                debug!(
                    "Sending message notification for user: {:}",
                    &payload.user_id
                );
                match message_payload(
                    &alert,
                    &title,
                    badge,
                    &payload.token,
                    payload_options.clone(),
                ) {
                    MessageAlert::Plain(apn_payload) => self.client.send(apn_payload).await,
                    MessageAlert::Protected(apn_payload) => self.client.send(apn_payload).await,
                }
            }

            PayloadKind::CalendarEvent(alert) => {
                let (title, body) = alert.render();
                let apn_payload = CalendarEventPayload {
                    aps: APS {
                        alert: Some(APSAlert::Default(DefaultAlert {
                            title: Some(&title),
                            subtitle: None,
                            body: Some(&body),
                            title_loc_key: None,
                            title_loc_args: None,
                            action_loc_key: None,
                            loc_key: None,
                            loc_args: None,
                            launch_image: None,
                        })),
                        badge: self.get_badge_count(&payload.user_id).await,
                        sound: Some(APSSound::Sound("default")),
                        thread_id: None,
                        content_available: None,
                        category: None,
                        mutable_content: Some(1),
                        url_args: None,
                    },
                    device_token: &payload.token,
                    options: payload_options.clone(),
                    event_id: &alert.event_id,
                    server_id: &alert.server_id,
                    kind: alert.kind.as_str(),
                    occurrence_start: alert.occurrence_start,
                    channel_id: alert.channel_id.as_deref(),
                    offset_ms: alert.offset_ms,
                };

                debug!(
                    "Sending calendar event notification for user: {:}",
                    &payload.user_id
                );
                self.client.send(apn_payload).await
            }

            PayloadKind::BadgeUpdate(badge) => {
                let apn_payload = Payload {
                    aps: APS {
                        badge: Some(badge as u32),
                        ..Default::default()
                    },
                    device_token: &payload.token,
                    options: payload_options.clone(),
                    data: BTreeMap::new(),
                };

                debug!("Sending badge update for user: {:}", &payload.user_id);
                self.client.send(apn_payload).await
            }

            PayloadKind::DmCallStartEnd(alert) => {
                let started_at = alert.started_at.map_or(String::new(), |f| f.clone());

                let apn_payload = CallStartStopPayload {
                    aps: APS {
                        alert: None,
                        badge: self.get_badge_count(&payload.user_id).await,
                        sound: None,
                        thread_id: None,
                        content_available: None,
                        category: None,
                        mutable_content: Some(1),
                        url_args: None,
                    },
                    device_token: &payload.token,
                    options: payload_options.clone(),
                    initiator_id: &alert.initiator_id,
                    channel_id: &alert.channel_id,
                    started_at: &started_at,
                    ended: alert.ended,
                };

                debug!(
                    "Sending call start/stop notification for user: {:}",
                    &payload.user_id
                );
                self.client.send(apn_payload).await
            }
        };

        match resp {
            Err(Error::ResponseError(Response {
                error:
                    Some(ErrorBody {
                        reason: ErrorReason::BadDeviceToken | ErrorReason::Unregistered,
                        ..
                    }),
                ..
            })) => {
                info!(
                    "Removing APNS subscription id {:} (user: {:}) due to invalid token",
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
            resp => {
                resp?;
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::Value;

    use super::*;
    use crate::utils::protected::fixtures::{self, *};

    /// What `consume` sends to APNs for a message notification, as JSON
    fn sent(alert: &PushNotification) -> String {
        let title = format_title(alert);
        match message_payload(
            alert,
            &title,
            Some(3),
            "device-token",
            NotificationOptions::default(),
        ) {
            MessageAlert::Plain(apn_payload) => serde_json::to_string(&apn_payload).unwrap(),
            MessageAlert::Protected(apn_payload) => serde_json::to_string(&apn_payload).unwrap(),
        }
    }

    fn keys(value: &Value) -> BTreeSet<&str> {
        value
            .as_object()
            .expect("an object")
            .keys()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn apn_protected_alert_is_generic() {
        for alert in [
            fixtures::notification(true),
            fixtures::encrypted_on_unflagged_channel(),
        ] {
            let wire: Value = serde_json::from_str(&sent(&alert)).unwrap();
            let shown = &wire["aps"]["alert"];
            assert_eq!(shown["title"], PROTECTED_PUSH_TITLE, "{wire}");
            assert_eq!(shown["body"], PROTECTED_PUSH_BODY, "{wire}");
            assert_eq!(keys(shown), BTreeSet::from(["title", "body"]), "{wire}");
        }
    }

    #[test]
    fn apn_protected_payload_carries_only_routing_ids() {
        for alert in [
            fixtures::notification(true),
            fixtures::encrypted_on_unflagged_channel(),
        ] {
            let wire = sent(&alert);
            fixtures::assert_carries_nothing_forbidden("apn", &wire);

            let wire: Value = serde_json::from_str(&wire).unwrap();
            assert_eq!(keys(&wire), BTreeSet::from(["aps", "url"]), "{wire}");
            assert_eq!(wire["url"], URL);
            assert_eq!(wire["aps"]["thread-id"], CHANNEL_ID);
        }
    }

    /// The unprotected payload is byte-identical to what the arm built
    /// before S8-O4 (a verbatim copy of it below)
    #[test]
    fn apn_unprotected_payload_is_unchanged() {
        let alert = fixtures::notification(false);
        let title = format!("{AUTHOR_NAME} in #{CHANNEL_NAME}");
        let legacy = MessagePayload {
            aps: APS {
                alert: Some(APSAlert::Default(DefaultAlert {
                    title: Some(&title),
                    subtitle: None,
                    body: Some(&alert.body),
                    title_loc_key: None,
                    title_loc_args: None,
                    action_loc_key: None,
                    loc_key: None,
                    loc_args: None,
                    launch_image: None,
                })),
                badge: Some(3),
                sound: Some(APSSound::Sound("default")),
                thread_id: Some(alert.channel.id()),
                content_available: None,
                category: None,
                mutable_content: Some(1),
                url_args: None,
            },
            device_token: "device-token",
            options: NotificationOptions::default(),
            message: &alert.message,
            url: &alert.url,
            author_avatar: &alert.icon,
            author_display_name: &alert.author,
            channel_name: alert.channel.name().unwrap_or(&title),
        };

        let wire = sent(&alert);
        assert_eq!(wire, serde_json::to_string(&legacy).unwrap());
        // The fixture's names and avatar do reach an unprotected push, so
        // the protected tests above are not passing on an empty fixture
        assert!(wire.contains(AUTHOR_NAME) && wire.contains(CHANNEL_NAME));
        assert!(wire.contains(AVATAR_URL) && wire.contains(AUTHOR_ID));
    }
}
