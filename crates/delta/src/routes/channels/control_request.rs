//! "Ask for a turn" (pass-the-controller plan §2.4).
//!
//! A call participant raises a hand at a streaming participant: the server
//! validates, relays one `CallControlRequest` event PRIVATELY to the sharer,
//! and forgets it. Nothing is stored, nothing is granted, and no queue exists
//! server-side — the rotation order lives on the sharer's client precisely so
//! the server can never choose a controller (plan §0.4). Every actual turn
//! still travels the full offer→accept→arm path with its native dialog on the
//! sharer's machine; this route only moves the *suggestion*.
//!
//! The requester's identity is STAMPED from the authenticated user, never
//! read from the body (the captions-route rule): a request body is not an
//! identity source, and the sharer's client keys its "X asked for a turn" row
//! on `requester_id`, so a caller-supplied one would let anyone raise a hand
//! in someone else's name. Enforcement of who may ask is server-side too —
//! live call membership, `Connect`, and a live screen-video share to ask
//! about — plus its own tight ratelimit bucket (`control_request`), because
//! request spam at a streamer is the obvious abuse of a social feature.

use revolt_database::{
    events::client::EventV1,
    util::{permissions::perms, reference::Reference},
    voice::{get_voice_state, is_in_voice_channel, UserVoiceChannel},
    Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};
use rocket_empty::EmptyResponse;

/// # Ask For A Control Turn
///
/// Ask a participant who is streaming their screen for a turn at the
/// controls. The sharer receives a private `CallControlRequest` event their
/// client may surface next to the rotation queue; accepting is a deliberate
/// separate act (an offer, then the native arm dialog). The caller must be a
/// live participant of the call holding `Connect`, and the named sharer must
/// be publishing screen video right now.
#[openapi(tag = "Remote Control")]
#[post("/<target>/control/request", data = "<data>")]
pub async fn control_request(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataControlRequest>,
) -> Result<EmptyResponse> {
    super::remote_control::require_remote_control_enabled().await?;

    let data = data.into_inner();
    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    // Bots are refused on the standard voice-state grounds (colliding
    // `{user}:{server}` flags) — and a bot has no hands to want a turn.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // A self-request is a confused client, not a permissions question.
    if data.sharer == user.id {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = perms(db, &user).channel(&channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    // Deliberately NOT checked here: the sharer's `UseRemoteControl` bit.
    // That bit gates the OFFER (checked on the sharer, at offer time, where
    // it belongs); computing another user's permission set inside the
    // requester's request would add queries without adding enforcement —
    // a request to someone who cannot offer simply goes nowhere.
    // Also deliberately not checked: the requester's own `rc_capable`
    // claim. It is an unverifiable self-report and must never become an
    // enforcement input; the queue UI filters on it, the server does not.

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);

    if !is_in_voice_channel(&user.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }
    if !is_in_voice_channel(&data.sharer, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    // The addressee must be streaming right now — there is nothing to ask
    // for a turn AT otherwise, and requiring it bounds request spam to
    // windows where a real stream exists. Gate on `screen_video` (source 3
    // only), not the conflated `screensharing` flag, for the same reason
    // the offer predicate does: screen audio alone leaves nothing to drive.
    let publishing_screen_video = get_voice_state(&user_voice_channel, &data.sharer)
        .await?
        .is_some_and(|state| state.screen_video);
    if !publishing_screen_video {
        return Err(create_error!(FailedValidation {
            error: "sharer is not publishing screen video".to_string()
        }));
    }

    // PRIVATE to the sharer, like `RemoteControlOffered`: a raised hand is
    // between the asker and the streamer, and the channel topic's boundary
    // (ViewChannel) is wider than the call. `private` reaches all of the
    // sharer's sessions — the receiving client scopes to its live call.
    EventV1::CallControlRequest {
        channel_id: channel.id().to_string(),
        requester_id: user.id.clone(),
        sharer_id: data.sharer.clone(),
    }
    .private(data.sharer)
    .await;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, update_voice_state, UserVoiceChannel,
        },
        Channel, Member, User,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

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

    async fn ask<'a>(
        harness: &'a TestHarness,
        token: &str,
        channel_id: &str,
        sharer_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/control/request"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", token.to_string()))
            .body(serde_json::json!({ "sharer": sharer_id }).to_string())
            .dispatch()
            .await
    }

    /// Bring a fresh server + voice channel + requester (a plain member) up.
    /// Split out because the `control_request` bucket is 3/10s and each test
    /// must stay under it — so the scenarios live in separate `async_test`
    /// fns, each with its OWN harness (hence its own ratelimit store), exactly
    /// like the offer tests do against their 2/10s bucket.
    async fn setup() -> (TestHarness, Channel, UserVoiceChannel, User, String, User) {
        let harness = TestHarness::new().await;
        let (_, _session_a, user_a) = harness.new_user().await; // sharer
        let (_, session_b, user_b) = harness.new_user().await; // requester
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");
        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        (harness, channel, uvc, user_a, session_b.token, user_b)
    }

    /// The membership + live-stream refusals — three asks, each flipping one
    /// condition, which sits exactly at the 3/10s bucket ceiling.
    #[test]
    fn control_request_gates_membership_and_share() {
        crate::util::test::rt().block_on(control_request_gates_membership_and_share_case())
    }

    async fn control_request_gates_membership_and_share_case() {
        let (harness, channel, uvc, user_a, token_b, user_b) = setup().await;

        // Requester not in the call: refused.
        let response = ask(&harness, &token_b, channel.id(), &user_a.id).await;
        assert_eq!(response.status(), Status::BadRequest);

        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state b");

        // Sharer not in the call: refused.
        let response = ask(&harness, &token_b, channel.id(), &user_a.id).await;
        assert_eq!(response.status(), Status::BadRequest);

        create_voice_state(&uvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("voice state a");

        // Sharer present but not publishing screen video: refused — a turn
        // request needs a live stream to be about.
        let response = ask(&harness, &token_b, channel.id(), &user_a.id).await;
        assert_eq!(response.status(), Status::BadRequest);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }

    /// The self-request refusal and the honest relay — two asks, both with a
    /// live stream present, in a fresh harness so the bucket is clean.
    #[test]
    fn control_request_rejects_self_then_relays() {
        crate::util::test::rt().block_on(control_request_rejects_self_then_relays_case())
    }

    async fn control_request_rejects_self_then_relays_case() {
        let (harness, channel, uvc, user_a, token_b, user_b) = setup().await;

        create_voice_state(&uvc, &user_a.id, Timestamp::now_utc())
            .await
            .expect("voice state a");
        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state b");
        update_voice_state(
            &uvc,
            &user_a.id,
            &v0::PartialUserVoiceState {
                screen_video: Some(true),
                screensharing: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("screen video flag");

        // Self-request: refused (the asker naming themselves), even with a
        // live stream.
        let response = ask(&harness, &token_b, channel.id(), &user_b.id).await;
        assert_eq!(response.status(), Status::BadRequest);

        // The honest path relays.
        let response = ask(&harness, &token_b, channel.id(), &user_a.id).await;
        assert_eq!(response.status(), Status::NoContent);

        delete_channel_voice_state(&uvc, &[user_a.id.clone(), user_b.id.clone()])
            .await
            .expect("teardown");
    }
}
