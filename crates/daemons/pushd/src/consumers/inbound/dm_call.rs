use std::{collections::HashMap, sync::Arc};

use crate::utils::{session_wants_call, Consumer};
use anyhow::Result;
use async_trait::async_trait;
use lapin::{message::Delivery, Channel, Connection};
use log::debug;
use revolt_database::{events::rabbit::*, Database, PushSubscriptionKind};

/// Whether a signal is about one person instead of about the call as a whole: they answered
/// on another of their devices, or they declined. Only a stop signal can be one of these. A
/// ring is always a ring, whatever else it carries, so a malformed ring still rings.
fn is_about_one_user(payload: &DmCallPayload) -> bool {
    payload.ended
        && matches!(
            payload.reason.as_deref(),
            Some(CALL_REASON_ANSWERED_ELSEWHERE | CALL_REASON_DECLINED)
        )
}

/// Who a call signal is pushed to.
///
/// `named` is the list the publisher narrowed the signal to and `members` is everyone in the
/// conversation. A named list is honored as it stands, minus anyone who is not in the
/// conversation. With no list, a ring and a plain end (cancelled, ended, no reason, or a
/// reason this build does not know) go to every member.
///
/// "Answered elsewhere" and "declined" are the exception. They tell one person's devices to
/// stop ringing, and the payload does not say who that person is: only the named list does.
/// Without one the signal goes to nobody, because handing it to every member would silence
/// a call that is still ringing for everyone else.
///
/// The caller never receives any of these. Their devices are not the ones ringing.
fn call_push_recipients(
    payload: &DmCallPayload,
    named: Option<&[String]>,
    members: &[String],
) -> Vec<String> {
    match named {
        Some(named) => named
            .iter()
            .filter(|user_id| members.contains(user_id) && **user_id != payload.initiator_id)
            .cloned()
            .collect(),
        None if is_about_one_user(payload) => Vec::new(),
        None => members
            .iter()
            .filter(|user_id| **user_id != payload.initiator_id)
            .cloned()
            .collect(),
    }
}

#[derive(Clone)]
#[allow(unused)]
pub struct DmCallConsumer {
    db: Database,
    connection: Arc<Connection>,
    channel: Arc<Channel>,
}

#[async_trait]
impl Consumer for DmCallConsumer {
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
        let _p: InternalDmCallPayload = serde_json::from_slice(&delivery.data)?;
        let payload = _p.payload;

        debug!("Received dm call start/stop event");

        let (revolt_database::Channel::DirectMessage { recipients, .. }
        | revolt_database::Channel::Group { recipients, .. }) =
            self.db.fetch_channel(&payload.channel_id).await?
        else {
            warn!(
                "Discarding dm call start/stop event for non-dm/group channel {}",
                payload.channel_id
            );

            return Ok(());
        };

        let named = _p.recipients.as_deref();

        if named.is_none() && is_about_one_user(&payload) {
            warn!(
                "Discarding dm call stop signal ({}) for channel {}: it names nobody",
                payload.reason.as_deref().unwrap_or_default(),
                payload.channel_id
            );
        }

        let call_recipients = call_push_recipients(&payload, named, &recipients);

        let config = revolt_config::config().await;
        let scope_enabled = config.features.push_session_scope;

        for user_id in call_recipients {
            if let Ok(sessions) = self.db.fetch_sessions(&user_id).await {
                for session in sessions {
                    if let Some(sub) = session.subscription {
                        // A session that asked not to be rung is skipped for a ring only. A
                        // stop signal still goes to it: a ring may have reached the device
                        // before the preference changed, and it has to be able to stop.
                        if !session_wants_call(&sub, &payload, scope_enabled) {
                            continue;
                        }

                        let mut sendable = PayloadToService {
                            notification: PayloadKind::DmCallStartEnd(payload.clone()),
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

                        self.publish_message(
                            payload.as_bytes(),
                            &config.pushd.exchange,
                            routing_key,
                        )
                        .await?;
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("dm_call.rs");

    const CALLER: &str = "01CALLER";
    const ANNA: &str = "01ANNA";
    const BEN: &str = "01BEN";
    const STRANGER: &str = "01STRANGER";

    /// A reason no build of this server has ever sent.
    const UNKNOWN_REASON: &str = "a_reason_from_a_newer_server";

    // The consumer's source with whitespace removed, as the pins below look for it.
    const NAMED_LIST: &str = "letnamed=_p.recipients.as_deref();";
    const DECISION: &str = "letcall_recipients=call_push_recipients(&payload,named,&recipients);";
    const WALK: &str = "foruser_idincall_recipients{";
    const SCOPE_SWITCH: &str = "letscope_enabled=config.features.push_session_scope;";
    const WANTS_CHECK: &str = "if!session_wants_call(&sub,&payload,scope_enabled){continue;}";

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|id| id.to_string()).collect()
    }

    fn ring() -> DmCallPayload {
        DmCallPayload {
            initiator_id: CALLER.to_string(),
            channel_id: "01CHANNEL".to_string(),
            started_at: Some("2026-09-23T00:00:00.000Z".to_string()),
            ended: false,
            call_id: Some("01CALL".to_string()),
            reason: None,
            video: None,
        }
    }

    fn stop(reason: Option<&str>) -> DmCallPayload {
        DmCallPayload {
            started_at: None,
            ended: true,
            reason: reason.map(|reason| reason.to_string()),
            ..ring()
        }
    }

    /// Who is pushed to in a three-person group: the caller and two people being rung.
    fn pushed_to(payload: &DmCallPayload, named: Option<Vec<String>>) -> Vec<String> {
        call_push_recipients(payload, named.as_deref(), &ids(&[CALLER, ANNA, BEN]))
    }

    /// Everything above this test module, with all whitespace removed so that a reformat
    /// does not break the pins.
    fn shipping() -> String {
        let end = SOURCE
            .find("#[cfg(test)]")
            .expect("the test module marker is in this file");
        SOURCE[..end].split_whitespace().collect()
    }

    /// Where `needle` first appears in the shipping source.
    fn at(shipping: &str, needle: &str) -> usize {
        shipping
            .find(needle)
            .unwrap_or_else(|| panic!("the consumer no longer contains `{}`", needle))
    }

    #[test]
    fn a_ring_goes_to_every_member_but_the_caller() {
        assert_eq!(pushed_to(&ring(), None), ids(&[ANNA, BEN]));
    }

    /// The publisher may narrow a ring to the people it wants rung. Someone on that list
    /// who is not in the conversation is never pushed to, and neither is the caller.
    #[test]
    fn a_narrowed_ring_reaches_only_the_named_members() {
        let named = Some(ids(&[BEN, STRANGER, CALLER]));

        assert_eq!(pushed_to(&ring(), named), ids(&[BEN]));
    }

    /// A call that was cancelled, a call that ended, a stop from a publisher that sends no
    /// reason, and a stop with a reason this build has never heard of all mean the same
    /// thing here: the ringing is over for everyone.
    #[test]
    fn a_plain_end_goes_to_every_member_but_the_caller() {
        for reason in [
            Some(CALL_REASON_CANCELLED),
            Some(CALL_REASON_ENDED),
            None,
            Some(UNKNOWN_REASON),
        ] {
            let got = pushed_to(&stop(reason), None);

            assert_eq!(got, ids(&[ANNA, BEN]), "reason {:?}", reason);
        }
    }

    /// The caller silencing one person's ring: a stop with one name on it.
    #[test]
    fn a_narrowed_plain_end_reaches_only_the_named_members() {
        for reason in [None, Some(CALL_REASON_CANCELLED), Some(CALL_REASON_ENDED)] {
            let got = pushed_to(&stop(reason), Some(ids(&[ANNA])));

            assert_eq!(got, ids(&[ANNA]), "reason {:?}", reason);
        }
    }

    /// Anna picked up on one device. Her other devices stop ringing; Ben's keep ringing.
    #[test]
    fn answered_elsewhere_reaches_only_the_person_who_answered() {
        let signal = stop(Some(CALL_REASON_ANSWERED_ELSEWHERE));

        assert_eq!(pushed_to(&signal, Some(ids(&[ANNA]))), ids(&[ANNA]));
    }

    /// Ben declined. His devices stop ringing; Anna's keep ringing.
    #[test]
    fn declined_reaches_only_the_person_who_declined() {
        let signal = stop(Some(CALL_REASON_DECLINED));

        assert_eq!(pushed_to(&signal, Some(ids(&[BEN]))), ids(&[BEN]));
    }

    /// The payload itself does not say who answered or declined. If the list that does is
    /// missing or empty, nobody is told: telling every member would stop a ring that is
    /// still live for the rest of them.
    #[test]
    fn a_personal_stop_that_names_nobody_reaches_nobody() {
        for reason in [CALL_REASON_ANSWERED_ELSEWHERE, CALL_REASON_DECLINED] {
            let signal = stop(Some(reason));

            assert!(pushed_to(&signal, None).is_empty(), "reason {}", reason);
            assert!(
                pushed_to(&signal, Some(Vec::new())).is_empty(),
                "reason {}",
                reason
            );
        }
    }

    /// A personal stop that names the caller, or someone outside the conversation, is
    /// dropped for them exactly as a ring would be.
    #[test]
    fn a_personal_stop_never_reaches_the_caller_or_a_stranger() {
        for reason in [CALL_REASON_ANSWERED_ELSEWHERE, CALL_REASON_DECLINED] {
            let got = pushed_to(&stop(Some(reason)), Some(ids(&[CALLER, STRANGER, BEN])));

            assert_eq!(got, ids(&[BEN]), "reason {}", reason);
        }
    }

    /// A reason only means something on a stop. A ring that carries one by mistake must
    /// still ring everybody instead of being thrown away for naming nobody.
    #[test]
    fn a_ring_carrying_a_personal_reason_still_rings_everyone() {
        for reason in [CALL_REASON_ANSWERED_ELSEWHERE, CALL_REASON_DECLINED] {
            let payload = DmCallPayload {
                reason: Some(reason.to_string()),
                ..ring()
            };

            let got = pushed_to(&payload, None);

            assert!(!is_about_one_user(&payload), "reason {}", reason);
            assert_eq!(got, ids(&[ANNA, BEN]), "reason {}", reason);
        }
    }

    #[test]
    fn only_answered_elsewhere_and_declined_are_about_one_user() {
        let answered_elsewhere = stop(Some(CALL_REASON_ANSWERED_ELSEWHERE));
        let declined = stop(Some(CALL_REASON_DECLINED));

        assert!(is_about_one_user(&answered_elsewhere));
        assert!(is_about_one_user(&declined));

        assert!(!is_about_one_user(&stop(Some(CALL_REASON_CANCELLED))));
        assert!(!is_about_one_user(&stop(Some(CALL_REASON_ENDED))));
        assert!(!is_about_one_user(&stop(Some(UNKNOWN_REASON))));
        assert!(!is_about_one_user(&stop(None)));
        assert!(!is_about_one_user(&ring()));
    }

    /// In a direct message the only member besides the caller is the person being called,
    /// wherever the two happen to sit in the channel's list.
    #[test]
    fn a_direct_message_signal_reaches_the_other_person() {
        let members = ids(&[ANNA, CALLER]);

        for payload in [ring(), stop(Some(CALL_REASON_CANCELLED)), stop(None)] {
            let got = call_push_recipients(&payload, None, &members);

            assert_eq!(got, ids(&[ANNA]), "reason {:?}", payload.reason);
        }
    }

    /// The decision above only matters if the consumer uses it, and hands it the list the
    /// publisher sent instead of one of its own.
    #[test]
    fn the_consumer_takes_its_recipients_from_the_decision() {
        let shipping = shipping();

        let named = at(&shipping, NAMED_LIST);
        let decided = at(&shipping, DECISION);
        let walked = at(&shipping, WALK);

        assert!(
            named < decided && decided < walked,
            "the consumer must walk exactly who the decision returns"
        );
        assert_eq!(shipping.matches("call_push_recipients(").count(), 2);
    }

    /// The per-session preference is checked under the switch from the config, against the
    /// very signal being sent, before anything is built or queued for that session.
    #[test]
    fn a_session_is_asked_whether_it_wants_this_call_push_before_anything_is_queued() {
        let shipping = shipping();

        let switch = at(&shipping, SCOPE_SWITCH);
        let check = at(&shipping, WANTS_CHECK);
        let built = at(&shipping, "PayloadToService{");
        let queued = at(&shipping, "self.publish_message(");

        assert!(
            switch < check && check < built && built < queued,
            "the check must come before the payload is built and queued"
        );
        assert_eq!(shipping.matches("session_wants_call(").count(), 1);
        assert_eq!(shipping.matches("self.publish_message(").count(), 1);
    }

    /// "Do not ring" is about the ring. The check has to be the one that looks at the signal
    /// and lets a stop through, because a ring can reach a device before the preference
    /// changes, or reach an older app, and that device still has to be told to stop. The
    /// plain per-class check knows nothing about the signal and would skip the stop too.
    #[test]
    fn a_stop_signal_is_never_skipped_for_a_session_that_must_not_ring() {
        let shipping = shipping();

        at(&shipping, WANTS_CHECK);

        assert_eq!(shipping.matches("session_wants(").count(), 0);
        assert_eq!(shipping.matches("PushClass").count(), 0);
    }

    /// A call push carries ids and nothing that would need looking anybody up. The two
    /// reads this consumer has always made, the channel and each recipient's sessions, are
    /// the only ones it makes.
    #[test]
    fn the_consumer_reads_the_channel_and_the_sessions_and_nothing_else() {
        let shipping = shipping();

        at(&shipping, "self.db.fetch_channel(&payload.channel_id)");
        at(&shipping, "self.db.fetch_sessions(&user_id)");

        assert_eq!(shipping.matches("self.db.").count(), 2);
    }
}
