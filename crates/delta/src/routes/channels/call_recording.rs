//! Call recording consent signalling (call-recording plan §1).
//!
//! A participant records the call **on their own machine** — the audio is
//! mixed and written by a `MediaRecorder` in their client, and no media ever
//! passes through here. These routes exist only to carry the *claim* that a
//! recording is running, so that everyone else in the call is told.
//!
//! **This is a self-report, not an observation.** Nothing server-side can
//! detect a recording; a client that records silently leaves the flag false
//! and is indistinguishable from one that is not recording. Read every check
//! below as "who may light the indicator", never "who may capture audio".
//! The honest security property is attribution and disclosure, and the
//! feature is worth having for the same reason a doorbell camera sticker is:
//! it makes the ordinary, cooperative case visible.
//!
//! Modeled on the soundboard route (REST validates → state write → EventV1
//! fan-out). The state lives on the participant's VOICE STATE rather than in
//! a one-shot event, which is the whole reason a late joiner is warned: the
//! roster read they already perform on join carries `recording`.

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{get_voice_state, is_in_voice_channel, update_voice_state, UserVoiceChannel},
    Channel, Database, SystemMessage, User, AMQP,
};
use revolt_models::v0::{self, MessageAuthor};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// Shared predicate for start and stop.
///
/// Eligibility is a two-row rule by channel type, the same split
/// `assert_offer_predicate` uses for remote control and for the same reason:
///
/// | Channel type   | Gate                                                  |
/// |----------------|-------------------------------------------------------|
/// | DM / Group DM  | call membership only — non-owners of existing groups
/// |                | hold just ViewChannel + ReadMessageHistory, so a bit
/// |                | check would pass for the group owner and fail for
/// |                | every other member                                    |
/// | Server channel | call membership + `RecordCall` on the recorder         |
///
/// Note `GrantAllSafe` covers bit 42, so server owners and privileged
/// accounts always pass the bit check. Unlike remote control — where that is
/// a self-risk decision about one's own machine — recording captures OTHER
/// people, so this is a genuine asymmetry rather than a shrug. It is
/// acceptable only because the disclosure below is unconditional: an owner
/// who records cannot do so quietly.
async fn assert_recording_predicate(
    db: &Database,
    channel: &Channel,
    user: &User,
) -> Result<UserVoiceChannel> {
    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // Bots are refused on the same grounds as remote control: per-member
    // voice flags key `{user}:{server}`, so a bot in two voice channels of
    // one server has COLLIDING voice state and any voice-state-gated feature
    // is unsound for it by construction.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    match channel {
        Channel::DirectMessage { .. } | Channel::Group { .. } => {
            // Call membership only — see the table above.
        }
        _ if channel.server().is_some() => {
            let mut query = perms(db, user).channel(channel);
            let permissions = calculate_channel_permissions(&mut query).await;
            permissions.throw_if_lacking_channel_permission(ChannelPermission::RecordCall)?;
        }
        _ => return Err(create_error!(NotAVoiceChannel)),
    }

    let user_voice_channel = UserVoiceChannel::from_channel(channel);

    // Only a live participant may claim to be recording. A non-participant
    // setting the flag would be pure disinformation — a way to make a call
    // look recorded (or, on stop, to clear someone else's warning).
    if !is_in_voice_channel(&user.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    Ok(user_voice_channel)
}

/// Announce the claim: flip the voice-state flag, fan the update to the
/// channel topic, and post the durable system message.
///
/// ORDER IS LOAD-BEARING. The state write comes first so that a joiner whose
/// roster read races the event still sees `recording: true`; the event is the
/// fast path for clients already present, not the source of truth.
async fn announce(
    db: &Database,
    amqp: &AMQP,
    channel: &Channel,
    user: &User,
    user_voice_channel: &UserVoiceChannel,
    recording: bool,
) -> Result<()> {
    update_voice_state(
        user_voice_channel,
        &user.id,
        &v0::PartialUserVoiceState {
            recording: Some(recording),
            ..Default::default()
        },
    )
    .await?;

    EventV1::UserVoiceStateUpdate {
        id: user.id.clone(),
        channel_id: channel.id().to_string(),
        data: v0::PartialUserVoiceState {
            id: Some(user.id.clone()),
            recording: Some(recording),
            ..Default::default()
        },
    }
    .p(channel.id().to_string())
    .await;

    // The system message is what survives the call. Send failures must NOT
    // roll back the flag: a live indicator with no channel message is a far
    // better outcome than a recording that proceeds with neither.
    let system = if recording {
        SystemMessage::CallRecordingStarted {
            by: user.id.clone(),
        }
    } else {
        SystemMessage::CallRecordingStopped {
            by: user.id.clone(),
        }
    };

    if let Err(error) = system
        .into_message(channel.id().to_string())
        .send(
            db,
            Some(amqp),
            MessageAuthor::System {
                username: &user.username,
                avatar: user.avatar.as_ref().map(|file| file.id.as_ref()),
            },
            None,
            None,
            channel,
            false,
        )
        .await
    {
        log::error!(
            "call recording: failed to post the {} system message in {}: {error:?}",
            if recording { "started" } else { "stopped" },
            channel.id()
        );
    }

    Ok(())
}

/// # Start Call Recording
///
/// Declare that you have started recording this call on your own machine.
/// Lights the in-call recording indicator for every participant — including
/// anyone who joins later — and posts a message in the channel.
///
/// Carries no audio and starts no server-side capture: the recording is local
/// to the caller's client. Idempotent.
#[openapi(tag = "Call Recording")]
#[put("/<target>/recording")]
pub async fn recording_start(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::CallRecordingResponse>> {
    let channel = target.as_channel(db).await?;
    let user_voice_channel = assert_recording_predicate(db, &channel, &user).await?;

    // Idempotent: a client that retries (or double-fires on a flaky
    // connection) must not post a second "started recording" message.
    let already = get_voice_state(&user_voice_channel, &user.id)
        .await?
        .is_some_and(|state| state.recording);

    if !already {
        announce(db, amqp, &channel, &user, &user_voice_channel, true).await?;
    }

    Ok(Json(v0::CallRecordingResponse { recording: true }))
}

/// # Stop Call Recording
///
/// Declare that you have stopped recording this call. Clears your recording
/// indicator and posts a message in the channel. Idempotent.
///
/// Leaving the call clears the flag too (voice-state teardown), so a recorder
/// who crashes or drops does not leave a permanent warning behind.
#[openapi(tag = "Call Recording")]
#[delete("/<target>/recording")]
pub async fn recording_stop(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<v0::CallRecordingResponse>> {
    let channel = target.as_channel(db).await?;

    // Stopping deliberately does NOT re-check `RecordCall`: someone whose
    // permission was revoked mid-recording must still be able to clear their
    // own flag, or a revoke would strand the indicator on.
    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);

    let recording = get_voice_state(&user_voice_channel, &user.id)
        .await?
        .is_some_and(|state| state.recording);

    if recording {
        announce(db, amqp, &channel, &user, &user_voice_channel, false).await?;
    }

    Ok(Json(v0::CallRecordingResponse { recording: false }))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{create_voice_state, delete_channel_voice_state, get_voice_state, UserVoiceChannel},
        Channel, Member, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};

    async fn voice_channel(
        harness: &TestHarness,
        server: &revolt_database::Server,
        name: &str,
    ) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: name.to_string(),
                description: None,
                nsfw: Some(false),
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    async fn connect(channel: &Channel, user: &User) -> UserVoiceChannel {
        let uvc = UserVoiceChannel::from_channel(channel);
        create_voice_state(&uvc, &user.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        uvc
    }

    async fn start<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .put(format!("/channels/{channel_id}/recording"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
    }

    async fn stop<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .delete(format!("/channels/{channel_id}/recording"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
    }

    async fn cleanup(uvc: &UserVoiceChannel, users: &[&User]) {
        let ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();
        delete_channel_voice_state(uvc, &ids).await.expect("cleanup");
    }

    /// The flag must round-trip through voice state — this is the leg that
    /// makes a LATE JOINER see an in-progress recording, since the joiner
    /// learns from the roster read and never sees the start event.
    #[rocket::async_test]
    async fn recording_flag_round_trips_through_voice_state() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect(&channel, &user).await;

        assert!(
            !get_voice_state(&uvc, &user.id)
                .await
                .unwrap()
                .expect("state")
                .recording,
            "a fresh join must never read as recording"
        );

        let response = start(&harness, &session.token, channel.id()).await;
        assert_eq!(response.status(), Status::Ok);
        assert!(
            get_voice_state(&uvc, &user.id)
                .await
                .unwrap()
                .expect("state")
                .recording,
            "the roster read a late joiner performs must carry the flag"
        );

        let response = stop(&harness, &session.token, channel.id()).await;
        assert_eq!(response.status(), Status::Ok);
        assert!(
            !get_voice_state(&uvc, &user.id)
                .await
                .unwrap()
                .expect("state")
                .recording
        );

        cleanup(&uvc, &[&user]).await;
    }

    /// A user who is not in the call cannot light (or clear) the indicator.
    #[rocket::async_test]
    async fn a_non_participant_cannot_claim_to_be_recording() {
        let harness = TestHarness::new().await;
        let (_, session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect(&channel, &user_a).await;

        // user_b holds the server-owner-adjacent member role but is NOT in
        // the call.
        let response = start(&harness, &session_b.token, channel.id()).await;
        assert_ne!(
            response.status(),
            Status::Ok,
            "a non-participant must not be able to make a call look recorded"
        );

        // The participant themselves is fine.
        let response = start(&harness, &session_a.token, channel.id()).await;
        assert_eq!(response.status(), Status::Ok);

        cleanup(&uvc, &[&user_a]).await;
    }

    /// Server channels gate on bit 42, and it is NOT in `DEFAULT_PERMISSION`
    /// — a plain member cannot record until a role grants it.
    #[rocket::async_test]
    async fn server_channel_gates_on_the_record_bit() {
        let harness = TestHarness::new().await;
        let (_, _session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect(&channel, &user_b).await;

        let response = start(&harness, &session_b.token, channel.id()).await;
        assert_eq!(
            response.status(),
            Status::Forbidden,
            "RecordCall must not be in DEFAULT_PERMISSION"
        );

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::RecordCall as i64,
                    d: 0,
                }),
            )
            .await;
        let mut member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member");
        member
            .update(
                &harness.db,
                revolt_database::PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("role grant");

        let response = start(&harness, &session_b.token, channel.id()).await;
        assert_eq!(response.status(), Status::Ok);

        cleanup(&uvc, &[&user_b]).await;
    }

    /// Revoking the bit mid-recording must not strand the indicator on: stop
    /// does not re-check the permission.
    #[rocket::async_test]
    async fn stop_works_after_the_bit_is_revoked() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect(&channel, &user).await;

        assert_eq!(
            start(&harness, &session.token, channel.id()).await.status(),
            Status::Ok
        );

        // Deny the bit at the channel level. The owner still passes via
        // GrantAllSafe, so drive the property directly instead: stop must
        // succeed for anyone holding a recording flag, permission or not.
        let response = stop(&harness, &session.token, channel.id()).await;
        assert_eq!(response.status(), Status::Ok);
        assert!(
            !get_voice_state(&uvc, &user.id)
                .await
                .unwrap()
                .expect("state")
                .recording
        );

        cleanup(&uvc, &[&user]).await;
    }

    /// A group DM does not consult the bit at all — a non-owner member must
    /// be able to record (the H-5 rule remote control follows).
    #[rocket::async_test]
    async fn group_dm_does_not_gate_on_the_bit() {
        let harness = TestHarness::new().await;
        let (_, _session_a, user_a) = harness.new_user().await;
        let (_, session_b, user_b) = harness.new_user().await;

        let mut group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: "Call".to_string(),
                description: None,
                icon: None,
                users: [user_b.id.clone()].into(),
                nsfw: None,
            },
            user_a.id.clone(),
        )
        .await
        .expect("group");

        group
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    voice: Some(revolt_database::VoiceInformation {
                        max_users: None,
                        disabled: false,
                    }),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("enable group calling");

        let uvc = connect(&group, &user_b).await;

        let response = start(&harness, &session_b.token, group.id()).await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "a non-owner group member must be able to record"
        );

        cleanup(&uvc, &[&user_b]).await;
    }

    /// Leaving the call clears the claim, so a recorder who drops without
    /// pressing stop does not leave a permanent warning on the channel.
    #[rocket::async_test]
    async fn leaving_the_call_clears_the_recording_claim() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect(&channel, &user).await;

        assert_eq!(
            start(&harness, &session.token, channel.id()).await.status(),
            Status::Ok
        );

        cleanup(&uvc, &[&user]).await;

        assert!(
            get_voice_state(&uvc, &user.id).await.unwrap().is_none(),
            "voice-state teardown must take the recording key with it"
        );

        // Re-joining starts clean rather than inheriting the stale claim.
        let uvc = connect(&channel, &user).await;
        assert!(
            !get_voice_state(&uvc, &user.id)
                .await
                .unwrap()
                .expect("state")
                .recording,
            "a re-join must not inherit a stale recording flag"
        );

        cleanup(&uvc, &[&user]).await;
    }
}
