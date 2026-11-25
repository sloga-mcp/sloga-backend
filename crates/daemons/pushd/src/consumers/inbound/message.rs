use std::{collections::HashMap, sync::Arc};

use crate::utils::{message_push_class, render_notification_content, session_wants, Consumer};
use anyhow::Result;
use async_trait::async_trait;
use lapin::{message::Delivery, Channel, Connection};
use log::debug;
use revolt_database::{events::rabbit::*, Database, PushSubscriptionKind, WebPushSubscription};

/// Whether one session takes the push for a message in this channel. A session that asked
/// for chats only keeps direct messages, groups and saved notes and gives up server channels,
/// nothing else. The answer is for this one session: the same user's other devices are asked
/// separately and are still notified.
fn wants(
    sub: &WebPushSubscription,
    channel: &revolt_models::v0::Channel,
    scope_enabled: bool,
) -> bool {
    session_wants(sub, message_push_class(channel), scope_enabled)
}

#[derive(Clone)]
#[allow(unused)]
pub struct MessageConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<Channel>,
}

#[async_trait]
impl Consumer for MessageConsumer {
    async fn create(
        db: Database,
        connection: Arc<Connection>,
        channel: Arc<Channel>,
    ) -> Self {
        Self {
            db,
            connection,
            channel,
        }
    }

    fn channel(&self) -> &Arc<Channel> {
        &self.channel
    }

    /// This consumer handles delegating messages into their respective platform queues.
    async fn consume(&self, delivery: Delivery) -> Result<()> {
        let mut payload: MessageSentPayload = serde_json::from_slice(&delivery.data)?;

        if let Ok(body) = render_notification_content(&payload.notification, &self.db).await {
            payload.notification.raw_body = Some(payload.notification.body);
            payload.notification.body = body;
        }

        debug!("Received message event on origin");

        if let Ok(sessions) = self
            .db
            .fetch_sessions_with_subscription(&payload.users)
            .await
        {
            let config = revolt_config::config().await;
            let scope_enabled = config.features.push_session_scope;
            for session in sessions {
                if let Some(sub) = session.subscription {
                    if !wants(&sub, &payload.notification.channel, scope_enabled) {
                        continue;
                    }

                    let mut sendable = PayloadToService {
                        notification: PayloadKind::MessageNotification(
                            payload.notification.clone(),
                        ),
                        token: sub.auth,
                        user_id: session.user_id,
                        session_id: session.id,
                        extras: HashMap::new(),
                    };

                    let routing_key = if sub.kind == Some(PushSubscriptionKind::UnifiedPush) {
                        sendable.extras.insert("p256dh".to_string(), sub.p256dh);
                        sendable.extras.insert("endpoint".to_string(), sub.endpoint);

                        &config.pushd.unifiedpush.queue
                    } else {
                        match sub.endpoint.as_str() {
                            "apn" => &config.pushd.apn.queue,
                            "fcm" => &config.pushd.fcm.queue,
                            endpoint => {
                                sendable.extras.insert("p256dh".to_string(), sub.p256dh);
                                sendable
                                    .extras
                                    .insert("endpoint".to_string(), endpoint.to_string());

                                &config.pushd.vapid.queue
                            }
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

#[cfg(test)]
mod tests {
    use super::wants;
    use revolt_database::WebPushSubscription;
    use revolt_models::v0::Channel;
    use serde_json::json;

    fn session(chats_only: Option<bool>, no_ring: Option<bool>) -> WebPushSubscription {
        WebPushSubscription {
            endpoint: "fcm".to_string(),
            p256dh: String::new(),
            auth: "token".to_string(),
            kind: None,
            chats_only,
            no_ring,
        }
    }

    fn channel(value: serde_json::Value) -> Channel {
        serde_json::from_value(value).expect("a channel")
    }

    fn direct_message() -> Channel {
        channel(json!({
            "channel_type": "DirectMessage",
            "_id": "01CHANNEL",
            "active": true,
            "recipients": ["01ALICE", "01BOB"],
        }))
    }

    fn group() -> Channel {
        channel(json!({
            "channel_type": "Group",
            "_id": "01CHANNEL",
            "name": "Friends",
            "owner": "01ALICE",
            "recipients": ["01ALICE", "01BOB"],
        }))
    }

    fn saved_notes() -> Channel {
        channel(json!({
            "channel_type": "SavedMessages",
            "_id": "01CHANNEL",
            "user": "01ALICE",
        }))
    }

    fn server_channel() -> Channel {
        channel(json!({
            "channel_type": "TextChannel",
            "_id": "01CHANNEL",
            "server": "01SERVER",
            "name": "general",
        }))
    }

    fn every_channel() -> [Channel; 4] {
        [direct_message(), group(), saved_notes(), server_channel()]
    }

    #[test]
    fn a_chats_only_session_gives_up_server_channels_and_nothing_else() {
        let chats_only = session(Some(true), None);

        assert!(wants(&chats_only, &direct_message(), true));
        assert!(wants(&chats_only, &group(), true));
        assert!(wants(&chats_only, &saved_notes(), true));
        assert!(!wants(&chats_only, &server_channel(), true));
    }

    #[test]
    fn without_the_preference_or_with_the_switch_off_every_message_is_delivered() {
        for channel in every_channel() {
            // No preference stored, which is every session that subscribed before the
            // preference existed.
            assert!(wants(&session(None, None), &channel, true));
            assert!(wants(&session(Some(false), None), &channel, true));
            // "Do not ring" is about calls and says nothing about messages.
            assert!(wants(&session(None, Some(true)), &channel, true));
            // The switch is off: the stored preference is ignored.
            assert!(wants(&session(Some(true), Some(true)), &channel, false));
        }
    }

    /// The code above the tests with all whitespace removed, so the pin below does not depend
    /// on how the file is formatted.
    fn shipping_source() -> String {
        include_str!("message.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("the code above the tests")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }

    #[test]
    fn a_skipped_session_skips_only_itself() {
        let source = shipping_source();

        // `continue` moves on to the next session. A `return` or a `break` in its place would
        // also drop the push for every session after this one, the user's other devices and
        // other users included.
        assert!(source.contains(
            "ifletSome(sub)=session.subscription{\
             if!wants(&sub,&payload.notification.channel,scope_enabled){continue;}\
             letmutsendable=PayloadToService{"
        ));
        assert!(source.contains("letscope_enabled=config.features.push_session_scope;"));
        // The payload is built in one place only, and that place is behind the check.
        assert_eq!(source.matches("PayloadToService{").count(), 1);
    }
}
