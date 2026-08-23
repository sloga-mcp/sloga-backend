use revolt_config::config;
use revolt_database::{
    util::{permissions::perms, reference::Reference},
    voice::{
        assert_call_caps_admit, delete_voice_state, get_channel_node, get_user_voice_channels,
        get_voice_channel_members, raise_if_in_voice, set_call_notification_recipients,
        set_channel_node, UserVoiceChannel, VoiceClient,
    },
    Database, Session, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};

use rocket::{serde::json::Json, State};

/// Device-qualified join (media E2EE, plan Q4): the claimed device must be a
/// registered E2EE device of the calling user AND the calling session must be
/// bound to it — a stolen web token cannot then impersonate a device identity
/// on the SFU. A bare join (no device id) is the pre-E2EE path and passes.
///
/// Shared by `join_call` and `screen_leg` (android-screen-share plan §2.1
/// step 5) rather than copied: a duplicated security check drifts, and the
/// leg's identity is derived from a device claim exactly as the primary's is.
pub(crate) async fn assert_device_bound_session(
    db: &Database,
    user: &User,
    session: &Session,
    device_id: Option<&str>,
) -> Result<()> {
    let Some(device_id) = device_id else {
        return Ok(());
    };

    crate::routes::mls::require_media_e2ee_enabled().await?;

    let identity = db
        .fetch_e2ee_identity(&user.id, device_id)
        .await
        .map_err(|_| {
            create_error!(FailedValidation {
                error: "joining device is not registered".to_string()
            })
        })?;

    identity.assert_bound_session(&session.id)
}

/// # Join Call
///
/// Asks the voice server for a token to join the call.
#[openapi(tag = "Voice")]
#[post("/<target>/join_call", data = "<data>")]
pub async fn call(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    session: Session,
    target: Reference<'_>,
    data: Json<v0::DataJoinCall>,
) -> Result<Json<v0::CreateVoiceUserResponse>> {
    if !voice_client.is_enabled() {
        return Err(create_error!(LiveKitUnavailable));
    }

    let v0::DataJoinCall {
        node,
        force_disconnect,
        recipients,
        device_id,
    } = data.into_inner();

    if user.bot.is_some() && force_disconnect == Some(true) {
        return Err(create_error!(IsBot));
    }

    assert_device_bound_session(db, &user, &session, device_id.as_deref()).await?;

    let channel = target.as_channel(db).await?;

    let Some(voice_info) = channel.voice() else {
        return Err(create_error!(NotAVoiceChannel));
    };

    let mut permissions = perms(db, &user).channel(&channel);

    let current_permissions = calculate_channel_permissions(&mut permissions).await;
    current_permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

    let user_voice_channel = UserVoiceChannel::from_channel(&channel);

    if get_voice_channel_members(&user_voice_channel)
        .await?
        .zip(voice_info.max_users)
        .is_some_and(|(ms, max_users)| ms.len() >= max_users)
        && !current_permissions.has(ChannelPermission::ManageChannel as u64)
    {
        return Err(create_error!(CannotJoinCall));
    }

    // Call-admission caps (D12 video-participant cap + T-20 MLS SFU-token
    // coupling), enforced against THIS channel for the joining user. This is
    // the shared front-door check (`assert_call_caps_admit`); the moderator
    // voice-move path enforces the identical caps so a privileged door cannot
    // bypass them. Both run OUTSIDE the E2EE device block above (which is
    // gated by require_media_e2ee_enabled), so a non-E2EE / downgraded client
    // that omits device_id cannot bypass them. The only reconnect exemption is
    // server-written membership (same-channel voice state for D12, MLS group
    // membership by user_id for T-20) — NEVER the client-controlled
    // `force_disconnect`, which the real client always sends (6.6 blocker).
    assert_call_caps_admit(db, &user_voice_channel, &user.id).await?;

    let existing_node = get_channel_node(channel.id()).await?;
    let has_existing_node = existing_node.is_some(); // we move existing_node in the next statement so this is the quickest way to know if we need to set it.

    let config = config().await;

    // A server-level voice region only decides where a room is OPENED; it
    // must never move a live room out from under its participants.
    let server_region = match channel.server() {
        Some(server_id) if !has_existing_node => {
            db.fetch_server(server_id).await?.voice_region
        }
        _ => None,
    };

    let node = resolve_join_node(existing_node, server_region, node, |candidate| {
        config.hosts.livekit.contains_key(candidate)
    })
    .ok_or_else(|| create_error!(UnknownNode))?;

    let node_host = config
        .hosts
        .livekit
        .get(&node)
        .ok_or_else(|| create_error!(UnknownNode))?
        .clone();

    if force_disconnect == Some(true) {
        // Finds and disconnects any existing voice connections by the user,
        // should only ever loop once but just to cover our backs.

        for previous_channel in get_user_voice_channels(&user.id).await? {
            // Reconnect ends any remote-control grant (plan §1): this path
            // removes the participant and the fresh token below is minted
            // with `can_publish_data: false`, so a controller's capability
            // silently dies here while Redis would keep reading "active".
            // Terminate explicitly — and never "helpfully" re-grant on
            // rejoin.
            revolt_database::voice::remote_control::release_remote_control_for_user(
                db,
                voice_client,
                &previous_channel,
                &user.id,
                "reconnected",
                // The old participant is still connected here — the
                // removal below is explicitly best-effort ("if this errors
                // its just a mismatching state - ignore"), so the
                // capability must be revoked rather than assumed gone.
                false,
            )
            .await;

            if let Some(node) = get_channel_node(&previous_channel.id).await? {
                // if this errors its just a mismatching state - ignore and proceed to still delete our state
                let _ = voice_client
                    .remove_user(&node, &user.id, &previous_channel.id)
                    .await;
            };

            delete_voice_state(&previous_channel, &user.id).await?;
        }
    } else {
        raise_if_in_voice(&user, &user_voice_channel).await?;
    }

    let token = voice_client
        .create_token(
            &node,
            db,
            &user,
            current_permissions,
            &channel,
            device_id.as_deref(),
        )
        .await?;

    let room = voice_client.create_room(&node, &channel).await?;

    if !has_existing_node {
        set_channel_node(channel.id(), &node).await?;
    }

    log::debug!("Created room {}", room.name);

    if let Some(recipients) = recipients {
        if room.num_participants == 0 && !recipients.is_empty() {
            set_call_notification_recipients(channel.id(), &user.id, &recipients).await?;
        }
    }

    Ok(Json(v0::CreateVoiceUserResponse {
        token,
        url: node_host.clone(),
    }))
}

/// Which LiveKit node a join lands on, in priority order:
/// 1. the node the room is already pinned to (first joiner decided),
/// 2. the server's configured voice region — only if that node is still
///    configured, so a region naming a decommissioned node degrades to
///    Auto instead of bricking the server's voice channels,
/// 3. the client's latency pick.
pub(crate) fn resolve_join_node(
    existing_node: Option<String>,
    server_region: Option<String>,
    requested: Option<String>,
    is_configured: impl Fn(&str) -> bool,
) -> Option<String> {
    existing_node
        .or_else(|| server_region.filter(|region| is_configured(region)))
        .or(requested)
}

// NB: these tests share the process-global redis_kiss connection, so (like
// the routes::mls suite) they are only reliable one-per-process — nextest,
// the repo's canonical runner, isolates them; under plain `cargo test` run
// with `--test-threads=1`.
#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, mls_cap_would_refuse,
            update_voice_state, video_roster_over_cap, UserVoiceChannel, MAX_VIDEO_PARTICIPANTS,
        },
        Channel, Member, MlsGroup, MlsGroupCreateOutcome, MlsMemberDevice, User,
        MAX_MLS_GROUP_MEMBERS,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

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

        channel
    }

    /// POST join_call with NO node: a request that passes the cap checks then
    /// fails deterministically at node resolution (400 UnknownNode) — the
    /// caps refuse with 409 BEFORE that point, so the two outcomes cleanly
    /// distinguish "cap fired" from "cap exempted" without a live LiveKit.
    async fn join_call<'a>(
        harness: &'a TestHarness,
        session_token: &str,
        channel_id: &str,
        force_disconnect: bool,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .post(format!("/channels/{channel_id}/join_call"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session_token.to_string()))
            .body(
                serde_json::to_string(&v0::DataJoinCall {
                    node: None,
                    force_disconnect: Some(force_disconnect),
                    recipients: None,
                    device_id: None,
                })
                .unwrap(),
            )
            .dispatch()
            .await
    }

    async fn assert_refused(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        error_type: &str,
    ) {
        assert_eq!(response.status(), Status::Conflict);
        assert!(
            response.into_string().await.unwrap().contains(error_type),
            "the refusal must be the distinguishable {error_type} error"
        );
    }

    async fn assert_past_caps(response: rocket::local::asynchronous::LocalResponse<'_>) {
        assert_eq!(response.status(), Status::BadRequest);
        assert!(
            response.into_string().await.unwrap().contains("UnknownNode"),
            "an exempt join must get past the caps to node resolution"
        );
    }

    #[test]
    fn video_cap_refuses_overflow_join_despite_force_disconnect() {
        crate::util::test::rt().block_on(video_cap_refuses_overflow_join_despite_force_disconnect_case())
    }

    async fn video_cap_refuses_overflow_join_despite_force_disconnect_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, user_a) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;
        let (_account_c, session_c, user_c) = harness.new_user().await;

        let channel = voice_channel(&harness, &user_a, &[&user_b, &user_c]).await;
        let voice_channel = UserVoiceChannel::from_channel(&channel);

        // Roster at EXACTLY the cap: B (a real member who will reconnect)
        // plus synthetic members, one of which has its camera on — the
        // voice-ingress-shaped Redis state the cap check reads
        create_voice_state(&voice_channel, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        let synthetic_ids: Vec<String> = (0..MAX_VIDEO_PARTICIPANTS - 1)
            .map(|index| format!("0SYNTHVOICEUSER{index:011}"))
            .collect();
        for user_id in &synthetic_ids {
            create_voice_state(&voice_channel, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
        update_voice_state(
            &voice_channel,
            &synthetic_ids[0],
            &v0::PartialUserVoiceState {
                camera: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("camera flag");

        // The real client ALWAYS sends force_disconnect:true — the flag must
        // not void the cap (6.6 live-proof blocker)
        let response = join_call(&harness, &session_c.token, channel.id(), true).await;
        assert_refused(response, "VideoCallFull").await;

        // ...and the non-force path stays refused
        let response = join_call(&harness, &session_c.token, channel.id(), false).await;
        assert_refused(response, "VideoCallFull").await;

        // B already holds voice state in THIS channel: a genuine same-channel
        // reconnect at the cap is exempt (it never grows the roster)
        let response = join_call(&harness, &session_b.token, channel.id(), true).await;
        assert_past_caps(response).await;

        // Redis is shared and the synthetic ids are fixed strings — drop the
        // seeded voice state so it does not accumulate across runs
        let mut seeded = synthetic_ids;
        seeded.push(user_b.id.clone());
        delete_channel_voice_state(&voice_channel, &seeded)
            .await
            .expect("cleanup");
    }

    #[test]
    fn mls_cap_refuses_overflow_join_despite_force_disconnect() {
        crate::util::test::rt().block_on(mls_cap_refuses_overflow_join_despite_force_disconnect_case())
    }

    async fn mls_cap_refuses_overflow_join_despite_force_disconnect_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, user_a) = harness.new_user().await;
        let (_account_b, session_b, user_b) = harness.new_user().await;
        let (_account_c, session_c, user_c) = harness.new_user().await;

        let channel = voice_channel(&harness, &user_a, &[&user_b, &user_c]).await;

        // Open MLS group at EXACTLY the roster cap, seeded at the DB layer
        // (the cap check reads the members mirror; no enrollment needed) —
        // B is a group member, C is not
        let mut members: Vec<MlsMemberDevice> = (0..MAX_MLS_GROUP_MEMBERS - 1)
            .map(|index| MlsMemberDevice {
                user_id: format!("0SYNTHETICUSER{index:012}"),
                device_id: format!("{index:032x}"),
            })
            .collect();
        members.push(MlsMemberDevice {
            user_id: user_b.id.clone(),
            device_id: "bb".repeat(16),
        });
        let outcome = harness
            .db
            .create_mls_group(
                &MlsGroup {
                    id: "11".repeat(32),
                    channel_id: channel.id().to_string(),
                    open: true,
                    created_by: members[0].clone(),
                    created_at: Timestamp::now_utc(),
                    current_epoch: 1,
                    members,
                    closed_at: None,
                    superseded_by: None,
                },
                None,
            )
            .await
            .expect("group seed");
        assert!(matches!(outcome, MlsGroupCreateOutcome::Created));

        // A non-member at the ceiling is refused the SFU token even with
        // force_disconnect:true (T-20 / CR-HIGH-2; 6.6 live-proof blocker)
        let response = join_call(&harness, &session_c.token, channel.id(), true).await;
        assert_refused(response, "MlsCallFull").await;

        // An existing group member (any device) rejoining at the ceiling is
        // exempt — blocking it would lock a crashed member out of a full call
        let response = join_call(&harness, &session_b.token, channel.id(), true).await;
        assert_past_caps(response).await;
    }

    /// The voice-ingress TOCTOU backstop predicates (`video_roster_over_cap` /
    /// `mls_cap_would_refuse`): after a join is recorded they must detect the
    /// overflow the check-then-act join leg could let race past — but stay
    /// inert at/below the cap so the legitimate cap-th member is never evicted.
    #[test]
    fn ingress_backstop_predicates_fire_only_over_cap() {
        crate::util::test::rt().block_on(ingress_backstop_predicates_fire_only_over_cap_case())
    }

    async fn ingress_backstop_predicates_fire_only_over_cap_case() {
        let harness = TestHarness::new().await;
        let (_account_a, _session_a, user_a) = harness.new_user().await;
        let (_account_b, _session_b, user_b) = harness.new_user().await;

        let channel = voice_channel(&harness, &user_a, &[&user_b]).await;
        let voice_channel = UserVoiceChannel::from_channel(&channel);

        // Seed the roster to EXACTLY the cap with one camera on (video active).
        let at_cap: Vec<String> = (0..MAX_VIDEO_PARTICIPANTS)
            .map(|index| format!("0SYNTHVIDEOUSER{index:011}"))
            .collect();
        for user_id in &at_cap {
            create_voice_state(&voice_channel, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
        update_voice_state(
            &voice_channel,
            &at_cap[0],
            &v0::PartialUserVoiceState {
                camera: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("camera flag");

        // At exactly the cap: NOT over (strict `>`) — the cap-th member stays.
        assert!(
            !video_roster_over_cap(&voice_channel).await.unwrap(),
            "roster at the cap must not be flagged over-cap"
        );

        // One more (the raced overflow) → over cap.
        create_voice_state(&voice_channel, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        assert!(
            video_roster_over_cap(&voice_channel).await.unwrap(),
            "roster past the cap must be flagged over-cap"
        );

        // No open MLS group → the ghost predicate never fires.
        assert!(!mls_cap_would_refuse(&harness.db, channel.id(), &user_b.id)
            .await
            .unwrap());

        // Open group at the roster cap: a non-member is a ghost (refuse), an
        // existing member is not.
        let mut members: Vec<MlsMemberDevice> = (0..MAX_MLS_GROUP_MEMBERS - 1)
            .map(|index| MlsMemberDevice {
                user_id: format!("0SYNTHETICUSER{index:012}"),
                device_id: format!("{index:032x}"),
            })
            .collect();
        members.push(MlsMemberDevice {
            user_id: user_a.id.clone(),
            device_id: "aa".repeat(16),
        });
        harness
            .db
            .create_mls_group(
                &MlsGroup {
                    id: "22".repeat(32),
                    channel_id: channel.id().to_string(),
                    open: true,
                    created_by: members[0].clone(),
                    created_at: Timestamp::now_utc(),
                    current_epoch: 1,
                    members,
                    closed_at: None,
                    superseded_by: None,
                },
                None,
            )
            .await
            .expect("group seed");
        assert!(
            mls_cap_would_refuse(&harness.db, channel.id(), &user_b.id)
                .await
                .unwrap(),
            "a non-member at the ceiling is a ghost the backstop must evict"
        );
        assert!(
            !mls_cap_would_refuse(&harness.db, channel.id(), &user_a.id)
                .await
                .unwrap(),
            "an existing member is exempt"
        );

        let mut seeded = at_cap;
        seeded.push(user_b.id.clone());
        delete_channel_voice_state(&voice_channel, &seeded)
            .await
            .expect("cleanup");
    }

    // ---- server voice region -------------------------------------------

    /// Pure resolution order: pinned room > server region > client pick,
    /// with a region naming an unconfigured node degrading to the client
    /// pick rather than failing the join.
    #[test]
    fn resolve_join_node_priority() {
        use super::resolve_join_node;
        let configured = |node: &str| node == "brazil" || node == "worldwide";
        let s = |v: &str| Some(v.to_string());

        // no room yet: the server's region beats the client's latency pick
        assert_eq!(
            resolve_join_node(None, s("brazil"), s("worldwide"), configured),
            s("brazil")
        );
        // a live room keeps its node even against a (newer) server region
        assert_eq!(
            resolve_join_node(s("worldwide"), s("brazil"), s("brazil"), configured),
            s("worldwide")
        );
        // no region (Auto): the client's pick
        assert_eq!(
            resolve_join_node(None, None, s("brazil"), configured),
            s("brazil")
        );
        // region names a decommissioned node: fall through to the client
        assert_eq!(
            resolve_join_node(None, s("moon"), s("worldwide"), configured),
            s("worldwide")
        );
        // nothing to go on at all
        assert_eq!(resolve_join_node(None, None, None, configured), None);
    }

    async fn edit_server_region(
        harness: &TestHarness,
        session_token: &str,
        server_id: &str,
        body: serde_json::Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .patch(format!("/servers/{server_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", session_token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// The server region only applies where a room is OPENED: with no room
    /// the join lands on the region's node; with a pinned room the pin wins
    /// and the region is ignored. A fake node on a closed port makes the
    /// "region won" outcome observable without a live LiveKit: the join gets
    /// past node resolution (no 400 UnknownNode) and fails on the SFU call
    /// instead, while the pinned bogus node fails AT resolution.
    #[test]
    fn server_region_decides_where_a_room_opens() {
        crate::util::test::rt().block_on(server_region_decides_where_a_room_opens_case())
    }

    async fn server_region_decides_where_a_room_opens_case() {
        // overwrite_config is once-per-process and must run BEFORE the
        // harness primes the config cache (nextest isolates processes)
        revolt_config::overwrite_config(|settings| {
            settings.api.livekit.nodes.insert(
                "testregion".to_string(),
                revolt_config::LiveKitNode {
                    url: "http://127.0.0.1:1".to_string(),
                    lat: 0.0,
                    lon: 0.0,
                    key: "testkey".to_string(),
                    secret: "testsecret-testsecret-testsecret".to_string(),
                    private: true,
                    remote: false,
                },
            );
            settings
                .hosts
                .livekit
                .insert("testregion".to_string(), "ws://127.0.0.1:1".to_string());
        })
        .await;

        let mut harness = TestHarness::new().await;
        let (_account, session, owner) = harness.new_user().await;
        let channel = voice_channel(&harness, &owner, &[]).await;
        let server_id = channel.server().expect("server channel").to_string();

        // unknown region is rejected on edit, and nothing is stored
        let (status, body) = edit_server_region(
            &harness,
            &session.token,
            &server_id,
            serde_json::json!({ "voice_region": "atlantis" }),
        )
        .await;
        assert_eq!(status, Status::BadRequest);
        assert!(body.contains("UnknownNode"), "{}", body);
        assert_eq!(
            harness.db.fetch_server(&server_id).await.unwrap().voice_region,
            None
        );

        // a configured region is stored, returned, and fanned out
        let (status, body) = edit_server_region(
            &harness,
            &session.token,
            &server_id,
            serde_json::json!({ "voice_region": "testregion" }),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        let returned: v0::Server = serde_json::from_str(&body).unwrap();
        assert_eq!(returned.voice_region.as_deref(), Some("testregion"));
        harness
            .wait_for_event(&server_id, |event| {
                matches!(
                    event,
                    revolt_database::events::client::EventV1::ServerUpdate { data, .. }
                        if data.voice_region.as_deref() == Some("testregion")
                )
            })
            .await;

        // no room yet + no client node: the region decides, so the join
        // gets PAST node resolution and dies on the (unreachable) SFU
        {
            let response = join_call(&harness, &session.token, &channel.id(), false).await;
            assert_eq!(
                response.status(),
                Status::InternalServerError,
                "region must resolve the node when no room exists"
            );
        }

        // a room pinned elsewhere keeps its node: the bogus pin is not a
        // configured host, so resolution itself fails — proving the region
        // was NOT consulted
        revolt_database::voice::set_channel_node(channel.id(), "pinned-elsewhere")
            .await
            .expect("pin");
        {
            let response = join_call(&harness, &session.token, &channel.id(), false).await;
            assert_past_caps(response).await;
        }
        revolt_database::voice::delete_channel_node(channel.id())
            .await
            .expect("unpin");

        // removing the field returns the server to Auto
        let (status, body) = edit_server_region(
            &harness,
            &session.token,
            &server_id,
            serde_json::json!({ "remove": ["VoiceRegion"] }),
        )
        .await;
        assert_eq!(status, Status::Ok, "{body}");
        let returned: v0::Server = serde_json::from_str(&body).unwrap();
        assert_eq!(returned.voice_region, None);
        harness
            .wait_for_event(&server_id, |event| {
                matches!(
                    event,
                    revolt_database::events::client::EventV1::ServerUpdate { clear, .. }
                        if clear.contains(&v0::FieldsServer::VoiceRegion)
                )
            })
            .await;

        // back on Auto with no client pick there is nothing to resolve
        let response = join_call(&harness, &session.token, &channel.id(), false).await;
        assert_past_caps(response).await;
    }

    /// ManageServer gates the region like every other server setting.
    #[test]
    fn server_region_requires_manage_server() {
        crate::util::test::rt().block_on(server_region_requires_manage_server_case())
    }

    async fn server_region_requires_manage_server_case() {
        let harness = TestHarness::new().await;
        let (_account, _owner_session, owner) = harness.new_user().await;
        let (_account_b, member_session, member) = harness.new_user().await;
        let channel = voice_channel(&harness, &owner, &[&member]).await;
        let server_id = channel.server().expect("server channel").to_string();

        let (status, _) = edit_server_region(
            &harness,
            &member_session.token,
            &server_id,
            serde_json::json!({ "voice_region": "worldwide" }),
        )
        .await;
        assert_eq!(status, Status::Forbidden);
    }
}
