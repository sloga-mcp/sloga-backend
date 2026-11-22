use std::{
    collections::{HashMap, HashSet},
    hash::RandomState,
    sync::Arc,
};

use crate::utils::{render_notification_content, session_wants, Consumer, PushClass};
use anyhow::Result;
use async_trait::async_trait;
use lapin::{message::Delivery, Channel, Connection};
use revolt_database::{
    events::rabbit::*, util::bulk_permissions::BulkDatabasePermissionQuery, Database, Member,
    MessageFlagsValue, PushSubscriptionKind, WebPushSubscription,
};
use revolt_models::v0::{MessageFlags, PushNotification};
use revolt_result::ToRevoltError;

/// Whether one session takes the push for an @everyone, @online or role mention. These only
/// happen in servers, so a session that asked for chats only gives them up. The answer is for
/// this one session: the same user's other devices are asked separately and are still notified.
fn wants(sub: &WebPushSubscription, scope_enabled: bool) -> bool {
    session_wants(sub, PushClass::MassMention, scope_enabled)
}

#[derive(Clone)]
#[allow(unused)]
pub struct MassMessageConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<Channel>,
}

impl MassMessageConsumer {
    async fn fire_notification_for_users(
        &self,
        push: &PushNotification,
        users: &[String],
    ) -> Result<()> {
        // A silent message still records its mentions; only the push is skipped.
        if MessageFlagsValue(push.message.flags).has(MessageFlags::SuppressNotifications) {
            return Ok(());
        }

        if let Ok(sessions) = self
            .db
            .fetch_sessions_with_subscription(users)
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
                        notification: PayloadKind::MessageNotification(push.clone()),
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

#[async_trait]
impl Consumer for MassMessageConsumer {
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

    /// This consumer handles adding mentions for all the users affected by a mass mention ping, and then sends out push notifications.
    async fn consume(&self, delivery: Delivery) -> Result<()> {
        let mut payload: MassMessageSentPayload = serde_json::from_slice(&delivery.data)?;
        let config = revolt_config::config().await;

        for push in payload.notifications.iter_mut() {
            if let Ok(body) = render_notification_content(push, &self.db)
                .await
                .to_internal_error()
            {
                push.raw_body = Some(push.body.clone());
                push.body = body;
            }
        }

        debug!("Received mass message event");

        // We should only ever receive clumped messages from a single channel, so it's safe to reuse this many times.
        let mut query: Option<BulkDatabasePermissionQuery<'_>> = None;
        let query_db = self.db.clone();

        for push in payload.notifications {
            if query.is_none() {
                query = Some(
                    BulkDatabasePermissionQuery::from_server_id(&query_db, &payload.server_id)
                        .await
                        .from_channel_id(push.channel.id().to_string()) // wrong channel model, so fetch the right one
                        .await,
                );
            }

            let existing_mentions: HashSet<String, RandomState> =
                if let Some(ref mentions) = push.message.mentions {
                    HashSet::from_iter(mentions.iter().cloned())
                } else {
                    HashSet::new()
                };

            // KNOWN QUIRK: if you mention @online and role(s), the offline members with the role(s) wont get pinged
            if let Some(ref query) = query {
                let flags = MessageFlagsValue(push.message.flags);
                if flags.has(MessageFlags::MentionsEveryone) {
                    let mut db_query = self
                        .db
                        .fetch_all_members_chunked(&payload.server_id)
                        .await?;

                    let mut exhausted = false;
                    let ack_chnl = vec![push.channel.id().to_string()];
                    loop {
                        let mut chunk: Vec<Member> = vec![];
                        for _ in 0..config.pushd.mass_mention_chunk_size {
                            if let Some(member) = db_query.next().await {
                                chunk.push(member);
                            } else {
                                exhausted = true;
                                break;
                            }
                        }

                        // Only members who can actually see the channel get the
                        // unread + push — @everyone must not leak into hidden
                        // channels (threads delegate visibility to their parent;
                        // the bulk query substitutes the parent already).
                        // The author never mentions themselves.
                        let mut q = query.clone().members(&chunk);
                        let userids: Vec<String> = q
                            .members_can_see_channel()
                            .await
                            .iter()
                            .filter_map(|(uid, viewable)| {
                                if *viewable && uid != &push.message.author {
                                    Some(uid.clone())
                                } else {
                                    None
                                }
                            })
                            .collect();

                        debug!("Viewable userids in chunk: {:?}", userids);

                        if let Err(err) = self
                            .db
                            .add_mention_to_many_unreads(push.channel.id(), &userids, &ack_chnl)
                            .await
                        {
                            revolt_config::capture_error(&err);
                        }

                        // ignore anyone in this list
                        let online_users = revolt_presence::filter_online(&userids).await;
                        let target_users: Vec<String> = userids
                            .iter()
                            .filter(|id| {
                                !online_users.contains(*id) && !existing_mentions.contains(*id)
                            })
                            .cloned()
                            .collect();

                        debug!(
                            "Userids after filter: {:?} (online: {:?}",
                            target_users, online_users
                        );

                        self.fire_notification_for_users(&push, &target_users)
                            .await?;

                        if exhausted {
                            break;
                        }
                    }
                } else if let Some(roles) = &push.message.role_mentions {
                    // role mentions
                    let mut role_members = self
                        .db
                        .fetch_all_members_with_roles_chunked(&payload.server_id, roles)
                        .await?;

                    let mut chunk = vec![];
                    let mut exhausted = false;

                    while !exhausted {
                        chunk.clear();

                        for _ in 0..config.pushd.mass_mention_chunk_size {
                            if let Some(member) = role_members.next().await {
                                chunk.push(member);
                            } else {
                                exhausted = true;
                                break;
                            }
                        }

                        let mut q = query.clone().members(&chunk);
                        let viewing_members: Vec<String> = q
                            .members_can_see_channel()
                            .await
                            .iter()
                            .filter_map(|(uid, viewable)| {
                                if *viewable
                                    && !existing_mentions.contains(uid)
                                    && uid != &push.message.author
                                {
                                    Some(uid.clone())
                                } else {
                                    None
                                }
                            })
                            .collect();

                        debug!("viewing members: {:?}", viewing_members);

                        let online = revolt_presence::filter_online(&viewing_members).await;
                        debug!("online: {:?}", online);

                        let targets: Vec<String> = viewing_members
                            .iter()
                            .filter(|m| !online.contains(*m))
                            .cloned()
                            .collect();

                        debug!("targets: {:?}", targets);

                        self.fire_notification_for_users(&push, &targets).await?;
                    }
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
        // "Do not ring" is about calls and says nothing about mentions.
        assert!(wants(&session(None, Some(true)), true));
        // The switch is off: the stored preference is ignored.
        assert!(wants(&session(Some(true), Some(true)), false));
    }

    /// The code above the tests with all whitespace removed, so the pin below does not depend
    /// on how the file is formatted.
    fn shipping_source() -> String {
        include_str!("mass_mention.rs")
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
        // the rest of the mentioned members included.
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
