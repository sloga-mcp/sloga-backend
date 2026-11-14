use std::{collections::HashMap, sync::Arc};

use crate::utils::{session_wants, Consumer, PushClass};
use anyhow::Result;
use async_trait::async_trait;
use lapin::{message::Delivery, Channel, Connection};
use log::debug;
use revolt_database::{events::rabbit::*, Database, PushSubscriptionKind, WebPushSubscription};

/// Whether one session takes a calendar-event push. Events belong to a server, so a session
/// that asked for chats only gives them up. The answer is for this one session: the same
/// user's other devices are asked separately and are still notified.
fn wants(sub: &WebPushSubscription, scope_enabled: bool) -> bool {
    session_wants(sub, PushClass::CalendarEvent, scope_enabled)
}

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
            let scope_enabled = config.features.push_session_scope;
            for session in sessions {
                if let Some(sub) = session.subscription {
                    if !wants(&sub, scope_enabled) {
                        continue;
                    }

                    let mut sendable = PayloadToService {
                        notification: PayloadKind::CalendarEvent(payload.clone()),
                        token: sub.auth,
                        user_id: session.user_id,
                        session_id: session.id,
                        extras: HashMap::new(),
                    };

                    let routing_key = if sub.kind == Some(PushSubscriptionKind::UnifiedPush) {
                        sendable.extras.insert("endpoint".to_string(), sub.endpoint);
                        sendable.extras.insert("p256dh".to_string(), sub.p256dh);

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

    #[test]
    fn only_a_chats_only_session_with_the_switch_on_is_skipped() {
        assert!(!wants(&session(Some(true), None), true));

        // No preference stored, which is every session that subscribed before the preference
        // existed.
        assert!(wants(&session(None, None), true));
        assert!(wants(&session(Some(false), None), true));
        // "Do not ring" is about calls and says nothing about events.
        assert!(wants(&session(None, Some(true)), true));
        // The switch is off: the stored preference is ignored.
        assert!(wants(&session(Some(true), Some(true)), false));
    }

    /// The code above the tests with all whitespace removed, so the pin below does not depend
    /// on how the file is formatted.
    fn shipping_source() -> String {
        include_str!("calendar_event.rs")
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
        // also drop the push for the recipient's other devices.
        assert!(source.contains(
            "ifletSome(sub)=session.subscription{\
             if!wants(&sub,scope_enabled){continue;}\
             letmutsendable=PayloadToService{"
        ));
        assert!(source.contains("letscope_enabled=config.features.push_session_scope;"));
        // The payload is built in one place only, and that place is behind the check.
        assert_eq!(source.matches("PayloadToService{").count(), 1);
    }
}
