use std::{borrow::Cow, collections::BTreeMap, io::Cursor, sync::Arc};

use crate::utils::{is_protected, CallPushTtl, Consumer, PROTECTED_PUSH_TITLE};
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
    author_avatar: &'a str,
    author_display_name: &'a str,
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
    channel_id: &'a str,
    started_at: &'a str,
    ended: bool,
    // The ring fields go out as text, the way the same keys travel on the other push
    // services, and are left out when unset: an app that predates them is sent exactly
    // the payload it has always been sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    call_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    video: Option<&'static str>,
}

impl<'a> CallStartStopPayload<'a> {
    /// The push an iPhone gets about a call. It identifies the call and nothing more: no
    /// caller name, no photo link and no group name leave the server in it, the app looks
    /// those up itself. It stays the silent push it has always been (no title, no sound),
    /// and the one delivery option it sets is `expiration`, the Unix time after which Apple
    /// stops trying to deliver it.
    fn new(
        alert: &'a DmCallPayload,
        device_token: &'a str,
        options: NotificationOptions<'a>,
        badge: Option<u32>,
        expiration: u64,
    ) -> Self {
        Self {
            aps: APS {
                alert: None,
                badge,
                sound: None,
                thread_id: None,
                content_available: None,
                category: None,
                mutable_content: Some(1),
                url_args: None,
            },
            options: NotificationOptions {
                apns_expiration: Some(expiration),
                ..options
            },
            device_token,
            initiator_id: &alert.initiator_id,
            channel_id: &alert.channel_id,
            started_at: alert.started_at.as_deref().unwrap_or(""),
            ended: alert.ended,
            call_id: alert.call_id.as_deref(),
            reason: alert.reason.as_deref(),
            video: alert.video.map(|video| if video { "true" } else { "false" }),
        }
    }
}

impl<'a> PayloadLike for CallStartStopPayload<'a> {
    fn get_device_token(&self) -> &'a str {
        self.device_token
    }
    fn get_options(&self) -> &NotificationOptions<'a> {
        &self.options
    }
}

/// Until when Apple may still deliver a call push, as the Unix time its `apns-expiration`
/// header takes, or `None` when the ring is already over and nothing must be sent.
///
/// Without an expiry Apple holds a push for a phone that is off or out of coverage and
/// delivers it whenever the phone comes back, long after the caller gave up.
fn call_push_expiration(alert: &DmCallPayload, now_unix: i64, ring_secs: usize) -> Option<u64> {
    match crate::utils::call_push_ttl(alert, now_unix, ring_secs) {
        CallPushTtl::Drop => None,
        CallPushTtl::Secs(secs) => Some(u64::try_from(now_unix).unwrap_or(0) + u64::from(secs)),
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
                let ring_secs = revolt_config::effective_call_ring_secs(
                    revolt_config::config().await.api.livekit.call_ring_duration,
                );

                // A ring whose time is already up is dropped before anything is read or
                // sent: this delivery may have waited in the queue while the daemon was down.
                let Some(expiration) =
                    call_push_expiration(&alert, crate::utils::now_unix(), ring_secs)
                else {
                    debug!(
                        "Dropping call notification past its ring time for user: {:}",
                        &payload.user_id
                    );
                    return Ok(());
                };

                let apn_payload = CallStartStopPayload::new(
                    &alert,
                    &payload.token,
                    payload_options.clone(),
                    self.get_badge_count(&payload.user_id).await,
                    expiration,
                );

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

    use revolt_database::iso8601_timestamp::{Duration, Timestamp};
    use serde_json::{json, Value};

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

    fn key_set(value: &Value) -> BTreeSet<&str> {
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
            assert_eq!(key_set(shown), BTreeSet::from(["title", "body"]), "{wire}");
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
            assert_eq!(key_set(&wire), BTreeSet::from(["aps", "url"]), "{wire}");
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

    fn keys(payload: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = payload
            .as_object()
            .expect("payload is a JSON object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    const NOW: i64 = 1_800_000_000;
    const RING_SECS: usize = 45;
    const EXPIRES: u64 = 1_800_000_045;

    /// A call signal the way a publisher that predates the ring fields queues it.
    fn call_alert() -> DmCallPayload {
        DmCallPayload {
            initiator_id: "01USER".to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: Some("2026-09-23T00:00:00.000Z".to_string()),
            ended: false,
            ..Default::default()
        }
    }

    /// The `started_at` a ring carries: the text voice-ingress makes from the join time.
    fn ring_started_at(unix: i64) -> Option<String> {
        Some(
            Timestamp::UNIX_EPOCH
                .checked_add(Duration::seconds(unix))
                .expect("a time in range")
                .to_string(),
        )
    }

    /// What the phone is sent for this signal, built the way the consumer builds it.
    fn call_value(alert: &DmCallPayload) -> Value {
        let payload = CallStartStopPayload::new(
            alert,
            "token",
            NotificationOptions::default(),
            Some(3),
            EXPIRES,
        );
        serde_json::to_value(&payload).unwrap()
    }

    /// The custom keys sit next to `aps` and match the FCM `push.dm.call` data keys.
    ///
    /// Changed when the ring fields arrived: the payload is now built by the function the
    /// consumer calls, from the queued call signal, where this test used to fill the struct
    /// in by hand. The pinned keys and values are the same as before, because a signal
    /// without the ring fields must still give an app that predates them exactly the
    /// payload it has always been sent.
    #[test]
    fn dm_call_payload_keys() {
        let alert = DmCallPayload {
            ended: true,
            ..call_alert()
        };
        let payload = CallStartStopPayload::new(
            &alert,
            "token",
            NotificationOptions::default(),
            None,
            EXPIRES,
        );

        // `to_value` keeps only the last of several identical keys, so check the raw text too.
        let raw = serde_json::to_string(&payload).unwrap();
        assert!(!raw.contains("camelCase"), "{raw}");

        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            keys(&value),
            ["aps", "channel_id", "ended", "initiator_id", "started_at"]
        );
        assert_eq!(value["initiator_id"], json!("01USER"));
        assert_eq!(value["channel_id"], json!("01CHANNEL"));
        assert_eq!(value["started_at"], json!("2026-09-23T00:00:00.000Z"));
        assert_eq!(value["ended"], json!(true));

        // A signal with no start time still sends the key, empty, as it always has
        let value = call_value(&DmCallPayload {
            started_at: None,
            ..alert.clone()
        });
        assert_eq!(value["started_at"], json!(""));
    }

    /// Nothing that names a person or a group may ride on a call push, so every key is
    /// checked against the short list a call is allowed to carry. `aps` is Apple's own
    /// envelope; inside it only the badge count and the flag that lets the app handle
    /// the push are allowed, which also keeps the push free of a title, a body and a sound.
    #[test]
    fn call_payload_has_no_key_outside_the_pinned_set() {
        const PINNED: [&str; 8] = [
            "initiator_id",
            "channel_id",
            "started_at",
            "ended",
            "duration",
            "call_id",
            "reason",
            "video",
        ];

        let ring = DmCallPayload {
            call_id: Some("01CALL".to_string()),
            video: Some(true),
            ..call_alert()
        };
        let ended = DmCallPayload {
            started_at: None,
            ended: true,
            call_id: Some("01CALL".to_string()),
            reason: Some(CALL_REASON_CANCELLED.to_string()),
            ..call_alert()
        };
        let everything = DmCallPayload {
            ended: true,
            call_id: Some("01CALL".to_string()),
            reason: Some(CALL_REASON_ENDED.to_string()),
            video: Some(false),
            ..call_alert()
        };

        assert_eq!(
            keys(&call_value(&ring)),
            [
                "aps",
                "call_id",
                "channel_id",
                "ended",
                "initiator_id",
                "started_at",
                "video"
            ]
        );
        assert_eq!(
            keys(&call_value(&ended)),
            [
                "aps",
                "call_id",
                "channel_id",
                "ended",
                "initiator_id",
                "reason",
                "started_at"
            ]
        );

        for alert in [call_alert(), ring, ended, everything] {
            let value = call_value(&alert);
            for key in keys(&value) {
                assert!(key == "aps" || PINNED.contains(&key), "{key} in {value}");
            }
            for key in keys(&value["aps"]) {
                assert!(["badge", "mutable-content"].contains(&key), "{key} in {value}");
            }
        }
    }

    #[test]
    fn call_id_is_sent_only_when_set() {
        let value = call_value(&DmCallPayload {
            call_id: Some("01CALL".to_string()),
            ..call_alert()
        });
        assert_eq!(value["call_id"], json!("01CALL"));

        assert!(call_value(&call_alert()).get("call_id").is_none());
    }

    #[test]
    fn reason_is_sent_only_when_set() {
        let value = call_value(&DmCallPayload {
            ended: true,
            reason: Some(CALL_REASON_ANSWERED_ELSEWHERE.to_string()),
            ..call_alert()
        });
        assert_eq!(value["reason"], json!("answered_elsewhere"));

        let value = call_value(&DmCallPayload {
            ended: true,
            ..call_alert()
        });
        assert!(value.get("reason").is_none());
    }

    /// `video` travels as the text "true" or "false", never as a JSON boolean, so an app
    /// reads it the same way from every push service.
    #[test]
    fn video_is_sent_as_text_only_when_set() {
        for (video, text) in [(true, "true"), (false, "false")] {
            let value = call_value(&DmCallPayload {
                video: Some(video),
                ..call_alert()
            });
            assert_eq!(value["video"], json!(text));
        }

        assert!(call_value(&call_alert()).get("video").is_none());
    }

    /// A call push keeps the push type, priority and topic every other push uses, and stays
    /// silent. Ringing an iPhone whose app is closed needs a different kind of push and is
    /// not something this payload may drift into.
    #[test]
    fn expiry_is_the_only_delivery_option_a_call_push_sets() {
        let alert = call_alert();
        let payload = CallStartStopPayload::new(
            &alert,
            "token",
            NotificationOptions {
                apns_id: None,
                apns_push_type: Some(PushType::Alert),
                apns_expiration: None,
                apns_priority: Some(Priority::High),
                apns_topic: Some("com.example.app"),
                apns_collapse_id: None,
            },
            None,
            EXPIRES,
        );

        let options = payload.get_options();
        assert_eq!(options.apns_expiration, Some(EXPIRES));
        assert!(matches!(options.apns_push_type, Some(PushType::Alert)), "{options:?}");
        assert!(matches!(options.apns_priority, Some(Priority::High)), "{options:?}");
        assert_eq!(options.apns_topic, Some("com.example.app"));
        assert!(options.apns_id.is_none(), "{options:?}");
        assert!(options.apns_collapse_id.is_none(), "{options:?}");
        assert_eq!(payload.get_device_token(), "token");

        // No title, body or sound, and no badge when there is none to show
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["aps"], json!({ "mutable-content": 1 }));
    }

    /// Apple takes the moment a push stops being valid, not a length of time. A ring is
    /// valid until its ringing time is over, counted from when the call started and not
    /// from when the push happens to be sent.
    #[test]
    fn a_ring_expires_when_its_ringing_time_is_over() {
        let ring = DmCallPayload {
            started_at: ring_started_at(NOW - 10),
            ..call_alert()
        };
        assert_eq!(call_push_expiration(&ring, NOW, RING_SECS), Some(1_800_000_035));

        // With no start time to count from, the ring gets its full length
        let ring = DmCallPayload {
            started_at: None,
            ..call_alert()
        };
        assert_eq!(call_push_expiration(&ring, NOW, RING_SECS), Some(1_800_000_045));
    }

    #[test]
    fn a_ring_past_its_time_is_not_sent() {
        for started in [NOW - 46, NOW - 3600] {
            let ring = DmCallPayload {
                started_at: ring_started_at(started),
                ..call_alert()
            };
            assert_eq!(call_push_expiration(&ring, NOW, RING_SECS), None);
        }
    }

    /// The push that stops the ringing is always sent, however long ago the call started,
    /// and is worth delivering for a minute.
    #[test]
    fn an_ended_call_push_lives_sixty_seconds() {
        for started_at in [None, ring_started_at(NOW - 3600)] {
            let ended = DmCallPayload {
                started_at,
                ended: true,
                ..call_alert()
            };
            assert_eq!(call_push_expiration(&ended, NOW, RING_SECS), Some(1_800_000_060));
        }
    }

    /// The stale check sits in `consume`, which cannot run without a connection to Apple,
    /// so its place is pinned on the source: the ring length goes through the one shared
    /// rule, the check reads the real clock, and it returns before the badge count is read
    /// or anything is sent.
    #[test]
    fn a_stale_ring_returns_before_anything_is_read_or_sent() {
        let arm: String = shipping_source()
            .split("PayloadKind::DmCallStartEnd(alert) => {")
            .nth(1)
            .expect("the call arm")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        let position = |needle: &str| {
            arm.find(needle)
                .unwrap_or_else(|| panic!("`{needle}` is missing from the call arm: {arm}"))
        };
        let ring_secs = position(
            "letring_secs=revolt_config::effective_call_ring_secs(\
             revolt_config::config().await.api.livekit.call_ring_duration",
        );
        let check = position(
            "letSome(expiration)=\
             call_push_expiration(&alert,crate::utils::now_unix(),ring_secs)else{",
        );
        let dropped = position("returnOk(());");
        let badge = position("self.get_badge_count(");
        let send = position("self.client.send(");

        assert!(ring_secs < check, "{arm}");
        assert!(check < dropped, "{arm}");
        assert!(dropped < badge, "{arm}");
        assert!(badge < send, "{arm}");
    }

    /// Every push from this consumer, calls included, goes out as an ordinary alert push.
    /// Moving calls to Apple's call-push type changes what the app must do on receipt and
    /// is a project of its own, so it cannot happen as a side effect of an edit here.
    #[test]
    fn calls_are_not_moved_to_another_push_type() {
        let shipping = shipping_source();
        assert_eq!(shipping.matches("apns_push_type:").count(), 1);
        assert!(shipping.contains("apns_push_type: Some(PushType::Alert),"));
        assert!(!shipping.contains("PushType::Voip"));
    }

    /// This file without its tests, so a pin never matches its own text.
    fn shipping_source() -> &'static str {
        include_str!("apn.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the code above the tests")
    }

    #[test]
    fn message_payload_keys() {
        let message: Message = serde_json::from_value(json!({
            "_id": "01MESSAGE",
            "channel": "01CHANNEL",
            "author": "01USER",
        }))
        .expect("minimal message");

        let payload = MessagePayload {
            aps: APS::default(),
            options: NotificationOptions::default(),
            device_token: "token",
            message: &message,
            url: "https://example.com/channel/01CHANNEL/01MESSAGE",
            author_avatar: "https://example.com/avatar.png",
            author_display_name: "Alice",
            channel_name: "general",
        };

        let raw = serde_json::to_string(&payload).unwrap();
        assert!(!raw.contains("camelCase"), "{raw}");

        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            keys(&value),
            [
                "aps",
                "author_avatar",
                "author_display_name",
                "channel_name",
                "message",
                "url"
            ]
        );
        assert_eq!(
            value["author_avatar"],
            json!("https://example.com/avatar.png")
        );
        assert_eq!(value["author_display_name"], json!("Alice"));
        assert_eq!(value["channel_name"], json!("general"));
    }
}
