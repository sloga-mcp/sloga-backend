//! Remote-control capability beacon (pass-the-controller plan §2.3 option A).
//!
//! A desktop client announces, once per call join, that it could RECEIVE a
//! control offer — i.e. that it is a build with a working native injection
//! layer. Without this, a rotation queue cannot tell a desktop participant
//! from a web/Android one, and an offer to the latter is answered by nothing
//! at all until the 90s TTL: in a game-night queue that reads as "it's stuck
//! on Dave", which is the feature's worst UX failure.
//!
//! **This is a self-report, not an observation** — the same discipline as the
//! `recording` flag, and the doc on `UserVoiceState::rc_capable` is the
//! contract. The server cannot verify the claim and nothing may treat it as
//! more than routing advice for the queue UI: a false claim buys nothing (the
//! offer still dies at the TTL; every real grant still passes the native arm
//! dialog on the sharer's machine), and an absent claim must never be
//! rendered as "cannot take control" — clients that predate this route are
//! fully capable and simply silent.
//!
//! Modeled on the recording routes (REST validates → voice-state write →
//! `UserVoiceStateUpdate` fan-out), minus the system message — a capability
//! is not an event anyone needs a durable record of. State is written before
//! the event so a joiner whose roster read races the fan-out still sees the
//! flag. There is no un-announce: capability is fixed for the lifetime of a
//! session, and leaving the call clears the key with the rest of the voice
//! state.

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{get_voice_state, is_in_voice_channel, update_voice_state, UserVoiceChannel},
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::State;
use rocket_empty::EmptyResponse;

/// # Announce Remote-Control Capability
///
/// Declare that this client could receive a remote-control offer in this
/// call. Marks the participant's voice state `rc_capable` for everyone in
/// the channel — advisory routing information for the "pass the controller"
/// queue, nothing more. Grants nothing, and is not verified. Idempotent.
#[openapi(tag = "Remote Control")]
#[put("/<target>/rc_capable")]
pub async fn rc_capable_announce(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    super::remote_control::require_remote_control_enabled().await?;

    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // Bots are refused for the same structural reason as every other
    // voice-state-gated feature: per-member voice flags key
    // `{user}:{server}`, and a bot in two voice channels of one server has
    // COLLIDING voice state.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);

    // Only a live participant may claim capability — a non-participant
    // writing roster fields would be pure disinformation, and the key
    // lifecycle (created false on join, deleted on leave) only holds for
    // participants.
    if !is_in_voice_channel(&user.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    // Idempotent: a client that retries on a flaky connection must not fan
    // a duplicate roster update at the channel.
    let already = get_voice_state(&user_voice_channel, &user.id)
        .await?
        .is_some_and(|state| state.rc_capable);
    if already {
        return Ok(EmptyResponse);
    }

    // State before event, like the recording announce: the event is the
    // fast path for clients already present, the voice state is the source
    // of truth a late joiner reads.
    update_voice_state(
        &user_voice_channel,
        &user.id,
        &v0::PartialUserVoiceState {
            rc_capable: Some(true),
            ..Default::default()
        },
    )
    .await?;

    // Channel topic on purpose: this is the same visibility class as the
    // rest of the voice-state flags (screensharing, recording) — a roster
    // fact, not speech — and the queue panel of ANY sharer in the call
    // needs it.
    EventV1::UserVoiceStateUpdate {
        id: user.id.clone(),
        channel_id: channel.id().to_string(),
        data: v0::PartialUserVoiceState {
            id: Some(user.id.clone()),
            rc_capable: Some(true),
            ..Default::default()
        },
    }
    .p(channel.id().to_string())
    .await;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, get_voice_state, UserVoiceChannel,
        },
        Channel,
    };
    use revolt_models::v0;
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
                spoiler: None,
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

    async fn announce<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .put(format!("/channels/{channel_id}/rc_capable"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
    }

    /// The claim must round-trip through voice state — that is the leg that
    /// lets a LATE-OPENED queue panel see who can take a turn, since the
    /// panel reads the roster, not the announce event.
    #[rocket::async_test]
    async fn rc_capable_requires_call_membership_and_persists() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = UserVoiceChannel::from_channel(&channel);

        // Not in the call yet: refused, nothing written.
        let response = announce(&harness, &session.token, channel.id()).await;
        assert_eq!(response.status(), Status::BadRequest);

        // Join: the flag starts un-claimed.
        create_voice_state(&uvc, &user.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        assert!(!get_voice_state(&uvc, &user.id)
            .await
            .expect("read")
            .expect("state")
            .rc_capable);

        for _ in 0..2 {
            // Twice: the second announce is the idempotence path.
            let response = announce(&harness, &session.token, channel.id()).await;
            assert_eq!(response.status(), Status::NoContent);
        }

        assert!(get_voice_state(&uvc, &user.id)
            .await
            .expect("read")
            .expect("state")
            .rc_capable);

        // Leaving clears the claim with the rest of the voice state — the
        // next session must re-announce, so a stale key can never mark a
        // web login as capable.
        delete_channel_voice_state(&uvc, &[user.id.clone()])
            .await
            .expect("teardown");
        assert!(get_voice_state(&uvc, &user.id)
            .await
            .expect("read")
            .is_none());
    }
}
