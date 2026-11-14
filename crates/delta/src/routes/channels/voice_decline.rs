use std::time::{SystemTime, UNIX_EPOCH};

use revolt_config::{config, effective_call_ring_secs};
use revolt_database::{
    events::{client::EventV1, rabbit::CALL_REASON_DECLINED},
    util::reference::Reference,
    voice::{
        claim_call_decline, get_call_ring, get_voice_state, has_call_answer_marker,
        ring_window_open, CallRing, UserVoiceChannel, VoiceClient,
    },
    Channel, Database, DmCallSignal, User, AMQP,
};
use revolt_result::{create_error, Result};

use rocket::State;
use rocket_empty::EmptyResponse;

/// The current time in unix seconds, as a ring record counts it.
///
/// A clock that cannot be read answers the far future, where every ring is
/// long over: a decline is then refused, never accepted for a ring whose age
/// is unknown.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since_epoch| since_epoch.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(i64::MAX)
}

/// The ring this request may decline, or `None` when there is nothing for it
/// to decline.
///
/// A decline counts only while the ring is still the requester's to turn
/// down: somebody else is ringing them, it is still ringing them
/// ([`still_ringing_for`]), and the requester is neither in the call nor on
/// the way in. `answering` covers the moment between an accepted answer and
/// the voice server reporting the join, when the requester has no voice
/// state yet and the ring is not yet marked answered: a second device must
/// not decline the call the first one is joining.
///
/// `ring_secs` is used as given: the route passes the value of
/// `revolt_config::effective_call_ring_secs`, never the raw setting.
#[allow(clippy::too_many_arguments)]
fn declinable_ring<'a>(
    call_signals: bool,
    ring: Option<&'a CallRing>,
    requester_id: &str,
    now: i64,
    ring_secs: usize,
    in_group: bool,
    in_call: bool,
    answering: bool,
) -> Option<&'a CallRing> {
    ring.filter(|ring| {
        call_signals
            && ring.initiator_id != requester_id
            && still_ringing_for(ring, now, ring_secs, in_group)
            && !in_call
            && !answering
    })
}

/// Whether the ring may still be ringing on the requester's devices: its
/// length and the grace for slow devices have not both run out.
///
/// In a direct message the only other person answering ends the ringing, so
/// an answered ring rings nobody and a decline of it is refused. In a group
/// one member answering leaves every other member's devices ringing, so
/// whether somebody answered plays no part there: the window is asked about
/// the ring as if nobody had, the same question the voice server asks before
/// it tells a late joiner's other devices to stop.
fn still_ringing_for(ring: &CallRing, now: i64, ring_secs: usize, in_group: bool) -> bool {
    if in_group {
        let unanswered = CallRing {
            answered: false,
            ..ring.clone()
        };
        ring_window_open(&unanswered, now, ring_secs)
    } else {
        ring_window_open(ring, now, ring_secs)
    }
}

/// The stop-ringing push for a ring its callee declined.
///
/// It is about one person, so it names them as the only recipient: the push
/// daemon sends a declined signal to nobody but the users it names. It stays
/// addressed from the ring's caller, because the push daemon never delivers a
/// call signal to the user it is addressed from. Addressed from the decliner
/// it would reach no device at all.
fn declined_signal(ring: &CallRing, channel_id: &str, decliner_id: &str) -> DmCallSignal {
    DmCallSignal {
        initiator_id: ring.initiator_id.clone(),
        channel_id: channel_id.to_string(),
        started_at: None,
        ended: true,
        recipients: Some(vec![decliner_id.to_string()]),
        call_id: Some(ring.call_id.clone()),
        reason: Some(CALL_REASON_DECLINED.to_string()),
        video: None,
    }
}

/// # Decline Call
/// Declines the call that is ringing you in a dm or group channel: your own
/// devices stop ringing, and in a dm the caller is told. The call itself is
/// left as it is, and in a group nobody else is told.
/// Takes no body.
/// Returns NoEffect when there is nothing to decline: no call is ringing, the
/// ring is over, a dm call was answered, you started it, you are in the call
/// or joining it, or you already declined it. Also NoEffect in servers.
/// Returns NotFound if you are not in the dm/group channel
#[openapi(tag = "Voice")]
#[put("/<target>/decline_call")]
pub async fn decline_call(
    db: &State<Database>,
    amqp: &State<AMQP>,
    voice: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    if !voice.is_enabled() {
        return Err(create_error!(LiveKitUnavailable));
    }

    // With the switch off no call has a ring to decline, and the answer is
    // given before anything is looked up.
    let config = config().await;
    let call_signals = config.features.call_signals;
    if !call_signals {
        return Err(create_error!(NoEffect));
    }

    let channel = target.as_channel(db).await?;
    let (recipients, caller_is_told) = match &channel {
        Channel::DirectMessage { recipients, .. } => (recipients, true),
        Channel::Group { recipients, .. } => (recipients, false),
        _ => return Err(create_error!(NoEffect)),
    };

    // Whoever is rung may decline, and a ring goes to every member of the
    // conversation whatever their permissions in it, so membership is the
    // whole test. Everyone else gets the answer a conversation that does not
    // exist gives, before any call state is read: an outsider learns nothing
    // about whether a call is ringing here.
    if !recipients.contains(&user.id) {
        return Err(create_error!(NotFound));
    }

    // Everything the decision needs is read first, and none of it is changed:
    // the ring record stays the caller's, and an answer marker stays for the
    // join it belongs to.
    let stored = get_call_ring(channel.id()).await?;
    let in_call = get_voice_state(
        &UserVoiceChannel {
            id: channel.id().to_string(),
            server_id: None,
        },
        &user.id,
    )
    .await?
    .is_some();
    let answering = has_call_answer_marker(channel.id(), &user.id).await?;

    let Some(ring) = declinable_ring(
        call_signals,
        stored.as_ref(),
        &user.id,
        now_unix(),
        effective_call_ring_secs(config.api.livekit.call_ring_duration),
        !caller_is_told,
        in_call,
        answering,
    ) else {
        return Err(create_error!(NoEffect));
    };

    // The one write, and the last thing that can refuse: a decline sent twice
    // (the phone and the app both report one press) is acted on once, and a
    // decline refused above never uses up the claim.
    if !claim_call_decline(&ring.call_id, &user.id).await? {
        return Err(create_error!(NoEffect));
    }

    // The decline now stands. Telling the devices is best effort: a signal
    // that fails to go out leaves a device ringing until the ring runs out,
    // which an error answer would not fix.
    if let Err(error) = amqp
        .dm_call_signal(declined_signal(ring, channel.id(), &user.id))
        .await
    {
        log::warn!(
            "call {} in {}: the declined signal did not reach the push daemon: {}",
            ring.call_id,
            channel.id(),
            error
        );
    }

    let declined = EventV1::VoiceCallDeclined {
        channel_id: channel.id().to_string(),
        call_id: ring.call_id.clone(),
        user_id: user.id.clone(),
    };

    // The decliner's own open apps stop ringing.
    declined.clone().private(user.id.clone()).await;

    // In a direct message the caller is told, and decides what to do about
    // their call. In a group the ring goes on for everyone else, and who
    // turned it down is nobody's business.
    if caller_is_told {
        declined.p(channel.id().to_string()).await;
    }

    Ok(EmptyResponse)
}

// The route tests below share the Redis-backed voice state with every other
// voice test, so they are reliable one per process: nextest isolates them,
// and under plain `cargo test` they need `--test-threads=1`.
#[cfg(test)]
mod test {
    use super::{declinable_ring, declined_signal, now_unix};
    use crate::util::test::{rt, without_comments, without_whitespace, TestHarness};
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        events::client::EventV1,
        voice::{
            create_voice_state, delete_channel_voice_state, get_call_ring,
            mark_call_ring_answered, set_call_answer_marker, set_call_ring,
            take_call_answer_marker, take_call_ring, CallRing, UserVoiceChannel, VoiceClient,
            CALL_RING_GRACE_SECS,
        },
        Channel, Session, User,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Method, Status};
    use ulid::Ulid;

    // ---- the decision ----------------------------------------------------

    const START: i64 = 1_700_000_000;
    const RING_SECS: usize = 45;

    /// The last second a decline still counts: the ring time and its grace
    const LAST_SECOND: i64 = START + RING_SECS as i64 + CALL_RING_GRACE_SECS;

    fn ring_from_caller(answered: bool) -> CallRing {
        CallRing {
            call_id: "call".to_string(),
            initiator_id: "caller".to_string(),
            started_at: "2023-11-14T22:13:20.000Z".to_string(),
            started_unix: START,
            video: false,
            answered,
        }
    }

    /// Every combination of the seven things that decide a decline. Three
    /// rows are accepted, all with the switch on, a requester who is not the
    /// caller, a ring time that is not over, and a requester who is neither
    /// in the call nor joining it: a direct message nobody answered, and a
    /// group whether or not somebody answered. Without a ring record no row
    /// is.
    #[test]
    fn a_decline_is_accepted_for_a_live_ring_of_somebody_else_only() {
        let mut accepted_rows = 0;
        for row in 0u8..128 {
            let bit = |n: u8| row & (1 << n) != 0;
            let (call_signals, by_caller, answered, late, in_call, answering, in_group) =
                (bit(0), bit(1), bit(2), bit(3), bit(4), bit(5), bit(6));

            let ring = ring_from_caller(answered);
            let requester = if by_caller { "caller" } else { "callee" };
            let now = if late { LAST_SECOND + 1 } else { LAST_SECOND };

            let accepted = declinable_ring(
                call_signals,
                Some(&ring),
                requester,
                now,
                RING_SECS,
                in_group,
                in_call,
                answering,
            );
            let expected = call_signals
                && !by_caller
                && (in_group || !answered)
                && !late
                && !in_call
                && !answering;
            assert_eq!(
                accepted.is_some(),
                expected,
                "switch {}, by the caller {}, answered {}, late {}, in the call {}, \
                 answering {}, in a group {}",
                call_signals,
                by_caller,
                answered,
                late,
                in_call,
                answering,
                in_group
            );
            if let Some(accepted) = accepted {
                assert_eq!(accepted, &ring, "the ring handed back is the stored one");
                accepted_rows += 1;
            }

            assert!(
                declinable_ring(
                    call_signals,
                    None,
                    requester,
                    now,
                    RING_SECS,
                    in_group,
                    in_call,
                    answering
                )
                .is_none(),
                "a decline was accepted with no ring record (row {})",
                row
            );
        }
        assert_eq!(accepted_rows, 3);
    }

    /// Whether a decline of `ring` in a direct message is accepted, at the
    /// usual ring length
    fn decide(
        call_signals: bool,
        ring: &CallRing,
        requester: &str,
        now: i64,
        in_call: bool,
        answering: bool,
    ) -> bool {
        declinable_ring(
            call_signals,
            Some(ring),
            requester,
            now,
            RING_SECS,
            false,
            in_call,
            answering,
        )
        .is_some()
    }

    /// Whether a callee's decline of `ring` in a group is accepted at `now`,
    /// at the usual ring length
    fn decide_in_group(ring: &CallRing, now: i64) -> bool {
        declinable_ring(
            true,
            Some(ring),
            "callee",
            now,
            RING_SECS,
            true,
            false,
            false,
        )
        .is_some()
    }

    /// The rows that matter most, each by name, so a failure says which rule
    /// went missing.
    #[test]
    fn each_refusal_of_a_decline_stands_on_its_own() {
        let ringing = ring_from_caller(false);
        let answered = ring_from_caller(true);

        assert!(
            decide(true, &ringing, "callee", START, false, false),
            "a callee declines a ring that just started"
        );
        assert!(
            decide(true, &ringing, "callee", LAST_SECOND, false, false),
            "a decline pressed on the last ring still counts"
        );

        assert!(
            !decide(false, &ringing, "callee", START, false, false),
            "the switch is off"
        );
        assert!(
            !decide(true, &ringing, "caller", START, false, false),
            "the caller declined their own ring"
        );
        assert!(
            !decide(true, &answered, "callee", START, false, false),
            "a direct message call was answered"
        );
        assert!(
            !decide(true, &ringing, "callee", LAST_SECOND + 1, false, false),
            "the ring time is over"
        );
        assert!(
            !decide(true, &ringing, "callee", i64::MAX, false, false),
            "the clock could not be read"
        );
        assert!(
            !decide(true, &ringing, "callee", START, true, false),
            "the requester is in the call"
        );
        assert!(
            !decide(true, &ringing, "callee", START, false, true),
            "another device of the requester is joining the call"
        );
    }

    /// In a group one member answering leaves the others ringing, so each of
    /// them can still decline until the ring time and its grace run out.
    #[test]
    fn a_group_member_declines_a_ring_somebody_else_answered() {
        let ringing = ring_from_caller(false);
        let answered = ring_from_caller(true);

        assert!(
            decide_in_group(&answered, START),
            "a group ring somebody answered still rings the others"
        );
        assert!(
            decide_in_group(&answered, LAST_SECOND),
            "a decline pressed on the last ring of an answered group call still counts"
        );
        assert!(
            decide_in_group(&ringing, START),
            "a group ring nobody answered"
        );
        assert!(
            !decide_in_group(&answered, LAST_SECOND + 1),
            "an answered group ring whose time is over"
        );
        assert!(
            !decide_in_group(&ringing, LAST_SECOND + 1),
            "a group ring whose time is over"
        );
    }

    /// What the push daemon needs to deliver the signal at all. It sends a
    /// declined signal only to the users named in `recipients`, and never to
    /// the user in `initiator_id`. So the decliner is the one recipient and
    /// the ring's caller stays the initiator: with no recipients the signal
    /// is dropped, and addressed from the decliner it reaches nobody.
    #[test]
    fn the_declined_signal_is_from_the_caller_and_names_only_the_decliner() {
        let ring = CallRing {
            video: true,
            ..ring_from_caller(false)
        };
        let signal = declined_signal(&ring, "channel", "decliner");

        assert_eq!(signal.initiator_id, "caller");
        assert_eq!(signal.recipients, Some(vec!["decliner".to_string()]));
        assert_eq!(signal.channel_id, "channel");
        assert!(signal.ended);
        assert_eq!(signal.reason.as_deref(), Some("declined"));
        assert_eq!(signal.call_id.as_deref(), Some("call"));
        assert_eq!(signal.started_at, None);
        assert_eq!(signal.video, None);
    }

    // ---- the route's source ----------------------------------------------

    const SOURCE: &str = include_str!("voice_decline.rs");

    /// This file as it ships: everything above the test module, comments cut
    fn shipping() -> String {
        let tests_at = SOURCE
            .find(concat!("#[cfg(", "test)]"))
            .expect("voice_decline.rs lost its test module");
        without_comments(&SOURCE[..tests_at])
    }

    /// `decline_call` from its signature to its last line, without whitespace
    fn decline_call_body() -> String {
        const LAST_LINE: &str = "Ok(EmptyResponse)";
        let shipping = shipping();
        let start = shipping
            .find("pub async fn decline_call(")
            .expect("voice_decline.rs no longer defines `decline_call`");
        let end = start
            + shipping[start..]
                .find(LAST_LINE)
                .expect("`decline_call` no longer ends in an empty response")
            + LAST_LINE.len();
        without_whitespace(&shipping[start..end])
    }

    const CLAIM: &str = "if!claim_call_decline(&ring.call_id,&user.id).await?";

    /// The order of the route: the switch before anything is looked up,
    /// membership before any call state is read, every read-only check before
    /// the claim, and the claim before anything is published. A claim taken
    /// earlier would be used up by a decline that is then refused, and a
    /// publish placed earlier would tell devices about a decline that never
    /// stood.
    #[test]
    fn the_claim_is_the_last_check_and_nothing_is_published_before_it() {
        let body = decline_call_body();
        let at = |needle: &str| {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "`decline_call` must have `{}` exactly once: {}",
                needle,
                body
            );
            body.find(needle).expect("counted above")
        };

        let steps = [
            "if!voice.is_enabled()",
            "if!call_signals",
            "target.as_channel(db).await?",
            "if!recipients.contains(&user.id)",
            "get_call_ring(channel.id()).await?",
            "get_voice_state(",
            "has_call_answer_marker(channel.id(),&user.id).await?",
            "declinable_ring(",
            CLAIM,
            ".dm_call_signal(declined_signal(ring,channel.id(),&user.id))",
            "declined.clone().private(user.id.clone()).await;",
            "declined.p(channel.id().to_string()).await;",
            "Ok(EmptyResponse)",
        ];
        let positions: Vec<usize> = steps.iter().map(|step| at(step)).collect();
        for (pair, names) in positions.windows(2).zip(steps.windows(2)) {
            assert!(
                pair[0] < pair[1],
                "`{}` must come before `{}`: {}",
                names[0],
                names[1],
                body
            );
        }

        let (before_claim, from_claim) = body.split_at(at(CLAIM));
        for publish in [
            "amqp.",
            "declined_signal(",
            "EventV1",
            ".private(",
            ".p(",
        ] {
            assert!(
                !before_claim.contains(publish),
                "`{}` stands before the claim: {}",
                publish,
                body
            );
        }

        // A claim that was already taken answers NoEffect, and after that
        // nothing can turn the answer into an error: what is published is
        // best effort.
        const REFUSED: &str = "{returnErr(create_error!(NoEffect));}";
        let after_claim = &from_claim[CLAIM.len()..];
        assert!(
            after_claim.starts_with(REFUSED),
            "a second claim must answer NoEffect: {}",
            body
        );
        let published = &after_claim[REFUSED.len()..];
        for way_out in ["?", "return", "create_error!"] {
            assert!(
                !published.contains(way_out),
                "`{}` after the claim: the decline stands, so the answer must too: {}",
                way_out,
                body
            );
        }
    }

    /// A direct message tells the caller, a group tells nobody, and every
    /// other kind of channel has no ring to decline.
    #[test]
    fn only_a_direct_message_publishes_to_the_channel() {
        let body = decline_call_body();
        for pinned in [
            "Channel::DirectMessage{recipients,..}=>(recipients,true),",
            "Channel::Group{recipients,..}=>(recipients,false),",
            "_=>returnErr(create_error!(NoEffect)),",
            "ifcaller_is_told{declined.p(channel.id().to_string()).await;}",
        ] {
            assert!(
                body.contains(pinned),
                "`decline_call` lost `{}`: {}",
                pinned,
                body
            );
        }
        assert_eq!(body.matches(".p(").count(), 1, "{}", body);
        assert_eq!(body.matches(".private(").count(), 1, "{}", body);
    }

    /// A decline ends nothing on the server. The route never writes or takes
    /// the ring record, never marks it answered, never collects an answer
    /// marker, and asks the voice client nothing beyond whether voice is on.
    #[test]
    fn a_decline_leaves_the_ring_the_roster_and_the_room_alone() {
        let shipping = shipping();
        for writer in [
            "set_call_ring",
            "take_call_ring",
            "mark_call_ring_answered",
            "set_call_answer_marker",
            "take_call_answer_marker",
            "take_call_video_hint",
            "delete_voice_state",
            "delete_channel_voice_state",
            "delete_voice_connection",
            "remove_user",
            "delete_room",
            "dm_call_updated",
        ] {
            assert!(
                !shipping.contains(writer),
                "voice_decline.rs names `{}`",
                writer
            );
        }

        let body = decline_call_body();
        assert_eq!(body.matches("voice.").count(), 1, "{}", body);
        assert!(body.contains("if!voice.is_enabled()"), "{}", body);
    }

    /// Phones send the request with no body and whatever content type the
    /// platform adds, so the route declares no body and no format.
    #[test]
    fn the_route_takes_no_body_and_no_format() {
        let shipping = without_whitespace(&shipping());
        assert!(
            shipping.contains(
                "#[openapi(tag=\"Voice\")]#[put(\"/<target>/decline_call\")]\
                 pubasyncfndecline_call(db:&State<Database>,amqp:&State<AMQP>,\
                 voice:&State<VoiceClient>,user:User,target:Reference<'_>,)\
                 ->Result<EmptyResponse>"
            ),
            "{}",
            shipping
        );
    }

    /// The route is mounted and documented. Left out of the list in
    /// `channels/mod.rs` it would be neither, and every decline a 404.
    #[test]
    fn the_route_is_mounted_and_in_the_openapi_spec() {
        let (routes, spec) = crate::routes::channels::routes();

        let route = routes
            .iter()
            .find(|route| route.name.as_deref() == Some("decline_call"))
            .expect("`decline_call` is not mounted");
        assert_eq!(route.method, Method::Put);
        assert_eq!(route.uri.path(), "/<target>/decline_call");
        assert!(
            route.format.is_none(),
            "the route must accept an empty request of any content type: {:?}",
            route.format
        );

        let operation = spec
            .paths
            .get("/{target}/decline_call")
            .and_then(|item| item.put.as_ref())
            .expect("PUT /{target}/decline_call is missing from the OpenAPI spec");
        assert!(
            operation.tags.iter().any(|tag| tag == "Voice"),
            "{:?}",
            operation.tags
        );
    }

    // ---- the route ---------------------------------------------------------

    /// A direct message `caller` is ringing `callee` in
    struct RingingDm {
        caller: User,
        caller_session: Session,
        callee: User,
        callee_session: Session,
        channel: Channel,
        ring: CallRing,
    }

    /// What every route test here needs from the build it runs in. Checked
    /// by name, so a build without them fails with the reason and not with
    /// an unexpected answer.
    async fn assert_calls_can_ring(harness: &TestHarness) {
        assert!(
            revolt_config::config().await.features.call_signals,
            "these tests need `features.call_signals` on"
        );
        assert!(
            harness
                .client
                .rocket()
                .state::<VoiceClient>()
                .expect("`VoiceClient`")
                .is_enabled(),
            "these tests need a configured voice node"
        );
    }

    /// Store a ring by `caller_id` that started this second
    async fn start_ring(channel_id: &str, caller_id: &str) -> CallRing {
        let ring = CallRing {
            call_id: Ulid::new().to_string(),
            initiator_id: caller_id.to_string(),
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            started_unix: now_unix(),
            video: false,
            answered: false,
        };
        set_call_ring(channel_id, &ring).await.expect("ring record");
        ring
    }

    async fn ringing_dm(harness: &TestHarness) -> RingingDm {
        assert_calls_can_ring(harness).await;

        let (_, caller_session, caller) = harness.new_user().await;
        let (_, callee_session, callee) = harness.new_user().await;
        let channel = Channel::create_dm(&harness.db, &caller, &callee)
            .await
            .expect("direct message");
        let ring = start_ring(channel.id(), &caller.id).await;

        RingingDm {
            caller,
            caller_session,
            callee,
            callee_session,
            channel,
            ring,
        }
    }

    /// PUT decline_call with no body. `as_a_phone` adds the form content type
    /// a phone's HTTP stack puts on an empty PUT.
    async fn decline(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        as_a_phone: bool,
    ) -> (Status, String) {
        let mut request = harness
            .client
            .put(format!("/channels/{}/decline_call", channel_id))
            .header(Header::new("x-session-token", session.token.to_string()));
        if as_a_phone {
            request = request.header(ContentType::Form);
        }

        let response = request.dispatch().await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    fn assert_declined(answer: &(Status, String)) {
        assert_eq!(answer, &(Status::NoContent, String::new()));
    }

    fn assert_no_effect(answer: &(Status, String)) {
        assert_eq!(answer.0, Status::BadRequest, "{}", answer.1);
        assert!(answer.1.contains("NoEffect"), "{}", answer.1);
    }

    /// (channel, call, decliner) of a decline event
    fn decline_fields(event: &EventV1) -> Option<(&str, &str, &str)> {
        match event {
            EventV1::VoiceCallDeclined {
                channel_id,
                call_id,
                user_id,
            } => Some((channel_id.as_str(), call_id.as_str(), user_id.as_str())),
            _ => None,
        }
    }

    fn is_decline(event: &EventV1) -> bool {
        decline_fields(event).is_some()
    }

    /// No decline event is waiting on any of `topics`.
    ///
    /// The harness reads every topic through one subscription and redis
    /// pub/sub is first in, first out on it, and the route awaits its
    /// publishes. So a marker published now arrives after everything the
    /// route published, and once it is seen all of that is in the harness's
    /// buffer. An event a test already waited for is not in the buffer, so
    /// after waiting for the expected ones this proves there were no more.
    async fn assert_no_further_decline(harness: &mut TestHarness, user_id: &str, topics: &[&str]) {
        let marker = Ulid::new().to_string();
        EventV1::ChannelAck {
            id: marker.clone(),
            user: user_id.to_string(),
            message_id: marker.clone(),
        }
        .private(user_id.to_string())
        .await;
        harness
            .wait_for_event(&format!("{}!", user_id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;

        for topic in topics {
            harness.assert_no_buffered_event(topic, is_decline);
        }
    }

    /// A callee declines a ringing direct-message call, sending the request
    /// as a phone does: 204, one event on their private topic and one on the
    /// channel, both naming the channel, the ring and the decliner. The
    /// caller's private topic gets nothing, and the ring record is untouched.
    #[test]
    fn a_callee_declines_a_ringing_direct_message_call() {
        rt().block_on(a_callee_declines_a_ringing_direct_message_call_case())
    }

    async fn a_callee_declines_a_ringing_direct_message_call_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let callee_topic = format!("{}!", call.callee.id);
        let caller_topic = format!("{}!", call.caller.id);

        let answer = decline(&harness, &call.callee_session, call.channel.id(), true).await;
        assert_declined(&answer);

        let expected = Some((
            call.channel.id(),
            call.ring.call_id.as_str(),
            call.callee.id.as_str(),
        ));
        let private = harness.wait_for_event(&callee_topic, is_decline).await;
        assert_eq!(decline_fields(&private), expected);
        let to_channel = harness.wait_for_event(call.channel.id(), is_decline).await;
        assert_eq!(decline_fields(&to_channel), expected);

        assert_no_further_decline(
            &mut harness,
            &call.callee.id,
            &[
                callee_topic.as_str(),
                call.channel.id(),
                caller_topic.as_str(),
            ],
        )
        .await;

        assert_eq!(
            get_call_ring(call.channel.id()).await.expect("ring read"),
            Some(call.ring.clone()),
            "a decline must leave the ring record as it was"
        );

        take_call_ring(call.channel.id()).await.expect("cleanup");
    }

    /// The caller cannot decline their own ring: NoEffect and no event
    /// anywhere. The callee can still decline it afterwards, so the refusal
    /// used nothing up.
    #[test]
    fn the_caller_cannot_decline_their_own_ring() {
        rt().block_on(the_caller_cannot_decline_their_own_ring_case())
    }

    async fn the_caller_cannot_decline_their_own_ring_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let callee_topic = format!("{}!", call.callee.id);
        let caller_topic = format!("{}!", call.caller.id);

        let answer = decline(&harness, &call.caller_session, call.channel.id(), false).await;
        assert_no_effect(&answer);
        assert_no_further_decline(
            &mut harness,
            &call.caller.id,
            &[
                caller_topic.as_str(),
                callee_topic.as_str(),
                call.channel.id(),
            ],
        )
        .await;

        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_declined(&answer);

        take_call_ring(call.channel.id()).await.expect("cleanup");
    }

    /// One press is reported twice (the phone and the app): the second
    /// decline of the same ring answers NoEffect and publishes nothing.
    #[test]
    fn a_second_decline_has_no_effect() {
        rt().block_on(a_second_decline_has_no_effect_case())
    }

    async fn a_second_decline_has_no_effect_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let callee_topic = format!("{}!", call.callee.id);

        let first = decline(&harness, &call.callee_session, call.channel.id(), true).await;
        assert_declined(&first);
        harness.wait_for_event(&callee_topic, is_decline).await;
        harness.wait_for_event(call.channel.id(), is_decline).await;

        let second = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_no_effect(&second);
        assert_no_further_decline(
            &mut harness,
            &call.callee.id,
            &[callee_topic.as_str(), call.channel.id()],
        )
        .await;

        take_call_ring(call.channel.id()).await.expect("cleanup");
    }

    /// In a group a decline is the decliner's own business: 204 and one
    /// event on their private topic, nothing on the group's topic and
    /// nothing for the caller or the other member.
    #[test]
    fn a_group_decline_tells_only_the_decliner() {
        rt().block_on(a_group_decline_tells_only_the_decliner_case())
    }

    async fn a_group_decline_tells_only_the_decliner_case() {
        let mut harness = TestHarness::new().await;
        assert_calls_can_ring(&harness).await;

        let (_, _caller_session, caller) = harness.new_user().await;
        let (_, callee_session, callee) = harness.new_user().await;
        let (_, _other_session, other) = harness.new_user().await;
        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Call".to_string(),
                description: None,
                icon: None,
                users: [callee.id.clone(), other.id.clone()].into(),
                nsfw: None,
                spoiler: None,
            },
            caller.id.clone(),
        )
        .await
        .expect("group");
        let ring = start_ring(group.id(), &caller.id).await;
        let callee_topic = format!("{}!", callee.id);
        let caller_topic = format!("{}!", caller.id);
        let other_topic = format!("{}!", other.id);

        let answer = decline(&harness, &callee_session, group.id(), false).await;
        assert_declined(&answer);

        let private = harness.wait_for_event(&callee_topic, is_decline).await;
        assert_eq!(
            decline_fields(&private),
            Some((group.id(), ring.call_id.as_str(), callee.id.as_str()))
        );

        assert_no_further_decline(
            &mut harness,
            &callee.id,
            &[
                callee_topic.as_str(),
                group.id(),
                caller_topic.as_str(),
                other_topic.as_str(),
            ],
        )
        .await;

        take_call_ring(group.id()).await.expect("cleanup");
    }

    /// In a group, one member answering leaves the others ringing: after the
    /// ring is marked answered another member still declines it, with the
    /// same 204 and the same single private event, and the record and its
    /// answered mark are left as they were.
    #[test]
    fn a_group_member_declines_after_somebody_else_answered() {
        rt().block_on(a_group_member_declines_after_somebody_else_answered_case())
    }

    async fn a_group_member_declines_after_somebody_else_answered_case() {
        let mut harness = TestHarness::new().await;
        assert_calls_can_ring(&harness).await;

        let (_, _caller_session, caller) = harness.new_user().await;
        let (_, _answerer_session, answerer) = harness.new_user().await;
        let (_, callee_session, callee) = harness.new_user().await;
        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Call".to_string(),
                description: None,
                icon: None,
                users: [answerer.id.clone(), callee.id.clone()].into(),
                nsfw: None,
                spoiler: None,
            },
            caller.id.clone(),
        )
        .await
        .expect("group");
        let ring = start_ring(group.id(), &caller.id).await;
        mark_call_ring_answered(&ring.call_id)
            .await
            .expect("answered mark");
        let answered = CallRing {
            answered: true,
            ..ring.clone()
        };
        assert_eq!(
            get_call_ring(group.id()).await.expect("ring read"),
            Some(answered.clone()),
            "the ring reads as answered"
        );
        let callee_topic = format!("{}!", callee.id);
        let caller_topic = format!("{}!", caller.id);
        let answerer_topic = format!("{}!", answerer.id);

        let answer = decline(&harness, &callee_session, group.id(), true).await;
        assert_declined(&answer);

        let private = harness.wait_for_event(&callee_topic, is_decline).await;
        assert_eq!(
            decline_fields(&private),
            Some((group.id(), ring.call_id.as_str(), callee.id.as_str()))
        );

        assert_no_further_decline(
            &mut harness,
            &callee.id,
            &[
                callee_topic.as_str(),
                group.id(),
                caller_topic.as_str(),
                answerer_topic.as_str(),
            ],
        )
        .await;

        assert_eq!(
            get_call_ring(group.id()).await.expect("ring read"),
            Some(answered),
            "a decline must leave the ring record and its answered mark as they were"
        );

        take_call_ring(group.id()).await.expect("cleanup");
    }

    /// Somebody who is not in the conversation gets NotFound, the very answer
    /// a channel that does not exist gives, and nothing is published. The
    /// ring was there to decline all along: the callee declines it afterwards.
    #[test]
    fn an_outsider_gets_the_answer_of_a_channel_that_does_not_exist() {
        rt().block_on(an_outsider_gets_the_answer_of_a_channel_that_does_not_exist_case())
    }

    async fn an_outsider_gets_the_answer_of_a_channel_that_does_not_exist_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let (_, outsider_session, outsider) = harness.new_user().await;
        let outsider_topic = format!("{}!", outsider.id);
        let callee_topic = format!("{}!", call.callee.id);
        let caller_topic = format!("{}!", call.caller.id);

        let refused = decline(&harness, &outsider_session, call.channel.id(), false).await;
        assert_eq!(refused.0, Status::NotFound, "{}", refused.1);
        assert!(refused.1.contains("NotFound"), "{}", refused.1);

        let nowhere = Ulid::new().to_string();
        let unknown = decline(&harness, &outsider_session, &nowhere, false).await;
        assert_eq!(
            refused, unknown,
            "an outsider can tell a conversation from a channel that does not exist"
        );

        assert_no_further_decline(
            &mut harness,
            &outsider.id,
            &[
                outsider_topic.as_str(),
                callee_topic.as_str(),
                caller_topic.as_str(),
                call.channel.id(),
            ],
        )
        .await;

        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_declined(&answer);

        take_call_ring(call.channel.id()).await.expect("cleanup");
    }

    /// A callee who is already in the call has answered it, whatever the
    /// record says: their decline is NoEffect. Out of the call again, the
    /// same ring is theirs to decline.
    #[test]
    fn a_callee_in_the_call_cannot_decline_it() {
        rt().block_on(a_callee_in_the_call_cannot_decline_it_case())
    }

    async fn a_callee_in_the_call_cannot_decline_it_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let callee_topic = format!("{}!", call.callee.id);
        let voice_channel = UserVoiceChannel::from_channel(&call.channel);

        create_voice_state(&voice_channel, &call.callee.id, Timestamp::now_utc())
            .await
            .expect("voice state");

        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_no_effect(&answer);
        assert_no_further_decline(
            &mut harness,
            &call.callee.id,
            &[callee_topic.as_str(), call.channel.id()],
        )
        .await;

        delete_channel_voice_state(&voice_channel, &[call.callee.id.clone()])
            .await
            .expect("cleanup");

        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_declined(&answer);

        take_call_ring(call.channel.id()).await.expect("cleanup");
    }

    /// While one device's answer is on its way into the call, another device
    /// of the same user cannot decline that call: NoEffect, nothing
    /// published, and the answer marker is left for the join it belongs to.
    /// With the marker gone the same ring is declined.
    #[test]
    fn a_callee_who_is_answering_cannot_decline() {
        rt().block_on(a_callee_who_is_answering_cannot_decline_case())
    }

    async fn a_callee_who_is_answering_cannot_decline_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let callee_topic = format!("{}!", call.callee.id);

        set_call_answer_marker(call.channel.id(), &call.callee.id)
            .await
            .expect("answer marker");

        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_no_effect(&answer);
        assert_no_further_decline(
            &mut harness,
            &call.callee.id,
            &[callee_topic.as_str(), call.channel.id()],
        )
        .await;

        assert!(
            take_call_answer_marker(call.channel.id(), &call.callee.id)
                .await
                .expect("marker read"),
            "the decline used up the answer marker"
        );

        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_declined(&answer);

        take_call_ring(call.channel.id()).await.expect("cleanup");
    }

    /// A ring that is over cannot be declined: one somebody answered, one
    /// whose ring time ran out long ago, and no ring at all each answer
    /// NoEffect and publish nothing.
    #[test]
    fn a_ring_that_is_over_cannot_be_declined() {
        rt().block_on(a_ring_that_is_over_cannot_be_declined_case())
    }

    async fn a_ring_that_is_over_cannot_be_declined_case() {
        let mut harness = TestHarness::new().await;
        let call = ringing_dm(&harness).await;
        let callee_topic = format!("{}!", call.callee.id);

        mark_call_ring_answered(&call.ring.call_id)
            .await
            .expect("answered mark");
        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_no_effect(&answer);

        // Taking the record collects the answered mark with it
        take_call_ring(call.channel.id()).await.expect("ring taken");
        let rang_out = CallRing {
            call_id: Ulid::new().to_string(),
            started_unix: now_unix() - 60 * 60,
            ..call.ring.clone()
        };
        set_call_ring(call.channel.id(), &rang_out)
            .await
            .expect("ring record");
        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_no_effect(&answer);

        take_call_ring(call.channel.id()).await.expect("ring taken");
        let answer = decline(&harness, &call.callee_session, call.channel.id(), false).await;
        assert_no_effect(&answer);

        assert_no_further_decline(
            &mut harness,
            &call.callee.id,
            &[callee_topic.as_str(), call.channel.id()],
        )
        .await;
    }
}
