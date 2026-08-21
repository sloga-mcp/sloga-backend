//! Native screen-share leg (android-screen-share plan §2.1).
//!
//! No web runtime on Android exposes screen capture — `getDisplayMedia()` is
//! absent in the WebView and non-functional in Chrome for Android — and a
//! native MediaProjection capture cannot be handed to the WebView's sealed
//! WebRTC stack as a `MediaStreamTrack`. So a phone shares its screen as a
//! SECOND LiveKit participant: the "screen leg", identity
//! `{user}:{device}:screen`, which publishes only the two screen sources,
//! subscribes to nothing, and is folded back into the user it belongs to by
//! every viewer.
//!
//! Deliberately NOT `join_call` with a flag. A leg never rings, never selects
//! or creates a node, never force-disconnects the user's other sessions and
//! never raises `AlreadyConnected` — it JOINS a call the caller is already in.
//! Sharing that route would mean threading "am I a leg" through every one of
//! those behaviours.
//!
//! The route mints nothing from the request body. The leg identity is derived
//! from the CURRENT primary mapping and the body's `device_id` only has to
//! MATCH it (step 6): a phone that is not the primary could otherwise mint
//! `user:phone:screen` while the user's desktop holds the call, and every
//! viewer would canonicalize that leg onto a non-leaf — mixed/loud for the
//! whole call (rev-2 review §0-R.2).

use revolt_config::config;
use revolt_database::{
    util::{permissions::perms, reference::Reference},
    voice::{
        get_channel_node, get_voice_channel_members, get_voice_participant_identity,
        is_in_voice_channel, screen_leg_identity, UserVoiceChannel, VoiceClient,
        MAX_VIDEO_PARTICIPANTS,
    },
    Database, Session, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

use super::voice_join::assert_device_bound_session;

/// The operator flag for the screen leg (plan §0.8).
///
/// It ships dark and must STAY dark until the viewer-side changes are live on
/// every surface: an un-updated viewer holds no frame key for the leg's
/// `{user}:{device}:screen` identity, so it takes a missing-key decrypt error
/// outside any rotation window and latches NOT-ENCRYPTED for the rest of the
/// call — a latch that does not clear when the leg leaves (plan §0.1).
///
/// `config()` is cached per process, so a flip needs a delta restart. Note
/// that voice-ingress is deliberately NOT gated on this flag: its leg branches
/// have to run for a hand-minted probe leg (§10.1) while the route is dark.
async fn require_screen_leg_enabled() -> Result<()> {
    if !config().await.features.screen_leg {
        return Err(create_error!(FeatureDisabled {
            feature: "screen_leg".to_string()
        }));
    }

    Ok(())
}

/// # Join Screen Leg
///
/// Asks the voice server for a publish-only token for a native screen-share
/// leg of the call this device is already in.
#[openapi(tag = "Voice")]
#[post("/<target>/screen_leg", data = "<data>")]
pub async fn screen_leg(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataScreenLeg>,
) -> Result<Json<v0::CreateVoiceUserResponse>> {
    // 1. Operator flag, then the SFU itself.
    require_screen_leg_enabled().await?;

    if !voice_client.is_enabled() {
        return Err(create_error!(LiveKitUnavailable));
    }

    let v0::DataScreenLeg { device_id } = data.into_inner();

    // 2. A bot has no screen to share, and no E2EE device to bind a leg to.
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    // 3. Channel must exist and be a voice channel.
    let channel = target.as_channel(db).await?;

    if channel.voice().is_none() {
        return Err(create_error!(NotAVoiceChannel));
    }

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);

    // 4. A leg without a primary is refused outright — it would be an orphan
    //    the SFU keeps alive with nobody to attribute it to. O(1) SISMEMBER on
    //    the same key `vc_members` is derived from.
    if !is_in_voice_channel(&user.id, &user_voice_channel).await? {
        return Err(create_error!(NotInVoiceChannel));
    }

    // 5. The same device-binding check `join_call` runs, from the same helper:
    //    the claimed device must be a registered E2EE device of this user with
    //    the calling session bound to it.
    assert_device_bound_session(db, &user, &session, device_id.as_deref()).await?;

    // 6. Primary binding (rev-2 review §0-R.2). A bound session proves "this
    //    is device X of user U"; it does NOT prove device X is the one in the
    //    call. Require the claim to match the identity the SFU actually knows,
    //    and derive the leg from THAT — never from the body.
    let primary = get_voice_participant_identity(channel.id(), &user.id).await?;

    let claimed_primary = match &device_id {
        Some(device_id) => format!("{}:{}", user.id, device_id),
        None => user.id.clone(),
    };

    if primary != claimed_primary {
        return Err(create_error!(FailedValidation {
            error: "leg must be minted by the device that is in the call".to_string()
        }));
    }

    let leg_identity = screen_leg_identity(&primary);

    // 7. The leg publishes screen video, so it needs exactly what starting a
    //    share from the WebView needs.
    let mut permissions = perms(db, &user).channel(&channel);
    let current_permissions = calculate_channel_permissions(&mut permissions).await;

    current_permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;
    current_permissions.throw_if_lacking_channel_permission(ChannelPermission::Video)?;

    // `get_allowed_sources` drops every video source when the account's video
    // limit is off, which would mint a token with no sources — and LiveKit
    // reads an empty `canPublishSources` as "no restriction". Refuse instead
    // of minting a grant whose meaning inverts.
    if !user.limits().await.video {
        return Err(create_error!(FeatureDisabled {
            feature: "video".to_string()
        }));
    }

    // 8. D12 video cap. The ingress track-publish leg would catch this anyway,
    //    but only after the user has sat through the MediaProjection consent
    //    dialog — and the remedy there is a silent server-side mute. Refusing
    //    here is the same gate with copy attached.
    if get_voice_channel_members(&user_voice_channel)
        .await?
        .map_or(0, |members| members.len())
        > MAX_VIDEO_PARTICIPANTS
    {
        return Err(create_error!(VideoCallFull {
            max: MAX_VIDEO_PARTICIPANTS
        }));
    }

    // 9. The primary created the room and pinned the node; a leg only ever
    //    follows it. No node selection, no `create_room`.
    let node = get_channel_node(channel.id())
        .await?
        .ok_or_else(|| create_error!(UnknownNode))?;

    let config = config().await;

    let node_host = config
        .hosts
        .livekit
        .get(&node)
        .ok_or_else(|| create_error!(UnknownNode))?
        .clone();

    let token = voice_client
        .create_screen_leg_token(&node, db, &user, &leg_identity, &channel)
        .await?;

    Ok(Json(v0::CreateVoiceUserResponse {
        token,
        url: node_host,
    }))
}

// NB: these tests share the process-global redis_kiss connection and drive the
// shared `rt()` runtime, exactly like the `voice_join` suite next door.
#[cfg(test)]
mod test {
    use crate::routes::e2ee::tests::publish_device;
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use livekit_api::access_token::TokenVerifier;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, set_channel_node,
            set_voice_participant_identity, UserVoiceChannel,
        },
        BotInformation, Channel, Member, PartialChannel, PartialUser, User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};

    /// The node every test pins with `set_channel_node`. It lives in the
    /// GITIGNORED `Revolt.overrides.toml` (as `member_edit.rs` also relies
    /// on): without the pin `get_channel_node` returns None and every request
    /// dies at step 9 instead of reaching the assertion under test.
    const NODE: &str = "worldwide";

    /// A server voice channel owned by `owner` with `members` added
    async fn voice_channel(harness: &TestHarness, owner: &User, members: &[&User]) -> Channel {
        let (server, _channels) = harness.new_server(owner).await;

        let channel = Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Voice".to_string(),
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
        .expect("voice channel");

        for member in members {
            Member::create(&harness.db, &server, member, None)
                .await
                .expect("member");
        }

        set_channel_node(channel.id(), NODE).await.expect("node");

        channel
    }

    /// Put `user` in the call with the SFU identity `identity` (what
    /// voice-ingress writes on `participant_joined`). Pass `None` for a bare,
    /// non-device-qualified primary — `get_voice_participant_identity` then
    /// falls back to the user id, which is the pre-E2EE shape.
    async fn join_as(channel: &Channel, user: &User, identity: Option<&str>) -> UserVoiceChannel {
        let user_voice_channel = UserVoiceChannel::from_channel(channel);

        create_voice_state(&user_voice_channel, &user.id, Timestamp::now_utc())
            .await
            .expect("voice state");

        if let Some(identity) = identity {
            set_voice_participant_identity(channel.id(), &user.id, identity)
                .await
                .expect("identity mapping");
        }

        user_voice_channel
    }

    async fn screen_leg<'a>(
        harness: &'a TestHarness,
        session_token: &str,
        channel_id: &str,
        device_id: Option<&str>,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/screen_leg"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session_token.to_string()))
            .body(
                serde_json::to_string(&v0::DataScreenLeg {
                    device_id: device_id.map(ToString::to_string),
                })
                .unwrap(),
            )
            .dispatch()
            .await
    }

    async fn assert_refused(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        error_type: &str,
    ) {
        assert_eq!(response.status(), status);
        assert!(
            response.into_string().await.unwrap().contains(error_type),
            "the refusal must be the distinguishable {error_type} error"
        );
    }

    /// The happy path, and the whole point of the route: the minted token is a
    /// publish-only grant on a leg identity DERIVED from the live primary
    /// mapping. Both identity forms — device-qualified and bare — because the
    /// bare one has its own grammar rule (three segments ALWAYS; `user:screen`
    /// would read as device = "screen", §0-R.3).
    #[test]
    fn screen_leg_token_is_publish_only_on_the_derived_leg_identity() {
        crate::util::test::rt()
            .block_on(screen_leg_token_is_publish_only_on_the_derived_leg_identity_case())
    }

    async fn screen_leg_token_is_publish_only_on_the_derived_leg_identity_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;

        let channel = voice_channel(&harness, &user, &[&user_b]).await;

        // A registered device of this user, bound to this session — the same
        // credential `join_call` requires.
        let device = publish_device(&harness, &account.id, &session.token, 1).await;
        let primary = format!("{}:{}", user.id, device.device_id);

        let user_voice_channel = join_as(&channel, &user, Some(&primary)).await;

        let response = screen_leg(
            &harness,
            &session.token,
            channel.id(),
            Some(&device.device_id),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let body: v0::CreateVoiceUserResponse =
            serde_json::from_str(&response.into_string().await.unwrap()).expect("token response");

        let node = revolt_config::config()
            .await
            .api
            .livekit
            .nodes
            .get(NODE)
            .expect("the `worldwide` node must be configured (Revolt.overrides.toml)")
            .clone();

        let claims = TokenVerifier::with_api_key(&node.key, &node.secret)
            .verify(&body.token)
            .expect("the leg token must verify against the node it names");

        assert_eq!(
            claims.sub,
            format!("{primary}:screen"),
            "the leg identity is derived from the live primary mapping"
        );
        assert_eq!(claims.video.room, channel.id());
        assert!(claims.video.room_join);
        assert!(claims.video.can_publish);
        assert_eq!(
            claims.video.can_publish_sources,
            vec!["screen_share".to_string(), "screen_share_audio".to_string()],
            "a leg may publish the two screen sources and nothing else"
        );
        assert!(
            !claims.video.can_subscribe,
            "a leg must never pull tracks down the phone's second WebRTC stack"
        );
        assert!(
            !claims.video.can_publish_data,
            "the data channel is an injection surface for the E2EE call machinery"
        );
        assert!(!claims.video.hidden);
        assert!(
            claims.exp.saturating_sub(claims.nbf) <= 10,
            "the leg token is short-lived by design — the plugin mints it \
             BETWEEN the MediaProjection consent dialog and connect"
        );
        assert_eq!(
            claims.attributes.get("leg").map(String::as_str),
            Some("screen")
        );
        assert_eq!(
            claims.attributes.get("platform").map(String::as_str),
            Some("android")
        );

        // A BARE primary (pre-E2EE / no device id) gets an EMPTY device
        // segment, never the two-segment `user:screen`.
        join_as(&channel, &user_b, None).await;

        let response = screen_leg(&harness, &session_b.token, channel.id(), None).await;
        assert_eq!(response.status(), Status::Ok);

        let body: v0::CreateVoiceUserResponse =
            serde_json::from_str(&response.into_string().await.unwrap()).expect("token response");
        let claims = TokenVerifier::with_api_key(&node.key, &node.secret)
            .verify(&body.token)
            .expect("verify");

        assert_eq!(claims.sub, format!("{}::screen", user_b.id));

        delete_channel_voice_state(&user_voice_channel, &[user.id.clone(), user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    /// A leg with no primary in the call is refused: an orphan leg is a
    /// participant nobody can attribute, and (viewer-side) reads as a
    /// non-enrolled stranger.
    #[test]
    fn screen_leg_refused_without_a_primary_in_the_call() {
        crate::util::test::rt().block_on(screen_leg_refused_without_a_primary_in_the_call_case())
    }

    async fn screen_leg_refused_without_a_primary_in_the_call_case() {
        let harness = TestHarness::new().await;
        let (_account, session, user) = harness.new_user().await;

        let channel = voice_channel(&harness, &user, &[]).await;

        let response = screen_leg(&harness, &session.token, channel.id(), None).await;
        assert_refused(response, Status::BadRequest, "NotInVoiceChannel").await;
    }

    /// The two-device hole (rev-2 review §0-R.2): a phone whose session IS
    /// bound to a registered device, but whose device is NOT the one holding
    /// the call, must not be able to mint a leg under the desktop's identity.
    #[test]
    fn screen_leg_refused_when_another_device_holds_the_call() {
        crate::util::test::rt()
            .block_on(screen_leg_refused_when_another_device_holds_the_call_case())
    }

    async fn screen_leg_refused_when_another_device_holds_the_call_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_user().await;

        let channel = voice_channel(&harness, &user, &[]).await;

        // The phone's own device: registered, and bound to this session.
        let phone = publish_device(&harness, &account.id, &session.token, 1).await;

        // ...but the DESKTOP is the participant the SFU knows.
        let desktop_device = "dd".repeat(16);
        let user_voice_channel = join_as(
            &channel,
            &user,
            Some(&format!("{}:{desktop_device}", user.id)),
        )
        .await;

        let response = screen_leg(
            &harness,
            &session.token,
            channel.id(),
            Some(&phone.device_id),
        )
        .await;
        assert_refused(response, Status::BadRequest, "FailedValidation").await;

        // The same hole from the other side: claiming NO device while a
        // device-qualified primary holds the call would derive `user::screen`
        // and orphan the real desktop leg namespace.
        let response = screen_leg(&harness, &session.token, channel.id(), None).await;
        assert_refused(response, Status::BadRequest, "FailedValidation").await;

        delete_channel_voice_state(&user_voice_channel, &[user.id.clone()])
            .await
            .expect("cleanup");
    }

    /// Device binding mirrors `join_call` (the shared helper): a session that
    /// is not bound to the claimed device — a stolen web token — is refused
    /// before anything is minted.
    #[test]
    fn screen_leg_refused_for_an_unbound_session() {
        crate::util::test::rt().block_on(screen_leg_refused_for_an_unbound_session_case())
    }

    async fn screen_leg_refused_for_an_unbound_session_case() {
        let harness = TestHarness::new().await;
        let (account, session, user) = harness.new_user().await;

        let channel = voice_channel(&harness, &user, &[]).await;
        let device = publish_device(&harness, &account.id, &session.token, 1).await;
        let user_voice_channel = join_as(
            &channel,
            &user,
            Some(&format!("{}:{}", user.id, device.device_id)),
        )
        .await;

        // A SECOND session of the same account: the device's binding now
        // names the first session, so this one is the "stolen token" case.
        let (_account, stolen) = harness.account_from_user(account.id.clone()).await;

        let response = screen_leg(
            &harness,
            &stolen.token,
            channel.id(),
            Some(&device.device_id),
        )
        .await;
        assert_refused(response, Status::Unauthorized, "NotAuthenticated").await;

        // An unregistered device id is refused too, before any Redis lookup.
        let response = screen_leg(
            &harness,
            &session.token,
            channel.id(),
            Some(&"ee".repeat(16)),
        )
        .await;
        assert_refused(response, Status::BadRequest, "FailedValidation").await;

        delete_channel_voice_state(&user_voice_channel, &[user.id.clone()])
            .await
            .expect("cleanup");
    }

    /// `Video` is what a screen share needs, and revoking it must close this
    /// door as well as the WebView's.
    #[test]
    fn screen_leg_refused_without_video_permission() {
        crate::util::test::rt().block_on(screen_leg_refused_without_video_permission_case())
    }

    async fn screen_leg_refused_without_video_permission_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, owner) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;

        let mut channel = voice_channel(&harness, &owner, &[&user_b]).await;

        // Deny Video to the default role; the owner keeps everything.
        channel
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::Video as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny video");

        let user_voice_channel = join_as(&channel, &user_b, None).await;

        let response = screen_leg(&harness, &session_b.token, channel.id(), None).await;
        assert_refused(response, Status::Forbidden, "MissingPermission").await;

        delete_channel_voice_state(&user_voice_channel, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    /// Bots have no screen and no E2EE device; refused at step 2, before the
    /// channel is even fetched.
    #[test]
    fn screen_leg_refused_for_a_bot() {
        crate::util::test::rt().block_on(screen_leg_refused_for_a_bot_case())
    }

    async fn screen_leg_refused_for_a_bot_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, owner) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;

        let channel = voice_channel(&harness, &owner, &[&user_b]).await;
        let user_voice_channel = join_as(&channel, &user_b, None).await;

        user_b
            .clone()
            .update(
                &harness.db,
                PartialUser {
                    bot: Some(BotInformation {
                        owner: owner.id.clone(),
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("bot user");

        let response = screen_leg(&harness, &session_b.token, channel.id(), None).await;
        assert_refused(response, Status::BadRequest, "IsBot").await;

        delete_channel_voice_state(&user_voice_channel, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    /// Flag dark ⇒ the route refuses before anything else runs. This is the
    /// posture the slice SHIPS in (plan §0.1), so it is the case that matters
    /// most in production right now.
    ///
    /// `overwrite_config` is once-per-process and must run BEFORE the harness
    /// primes the config cache; process isolation comes from nextest (the
    /// repo's canonical runner). Under plain `cargo test` this test must be
    /// filtered into a run of its own.
    #[test]
    fn screen_leg_refused_when_flag_dark() {
        crate::util::test::rt().block_on(screen_leg_refused_when_flag_dark_case())
    }

    async fn screen_leg_refused_when_flag_dark_case() {
        revolt_config::overwrite_config(|settings| {
            settings.features.screen_leg = false;
        })
        .await;

        let harness = TestHarness::new().await;
        let (_account, session, user) = harness.new_user().await;

        let channel = voice_channel(&harness, &user, &[]).await;
        let user_voice_channel = join_as(&channel, &user, None).await;

        let response = screen_leg(&harness, &session.token, channel.id(), None).await;
        assert_eq!(response.status(), Status::BadRequest);
        let body = response.into_string().await.unwrap();
        assert!(body.contains("FeatureDisabled"), "{body}");
        // Name the feature: an account with `limits.video` off raises
        // FeatureDisabled too, and a test that cannot tell the two apart
        // would keep passing with the flag lit.
        assert!(body.contains("screen_leg"), "{body}");

        delete_channel_voice_state(&user_voice_channel, &[user.id.clone()])
            .await
            .expect("cleanup");
    }
}
