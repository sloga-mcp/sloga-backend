use std::collections::HashSet;

use revolt_database::{
    events::client::EventV1,
    util::{
        permissions::{perms, DatabasePermissionQuery},
        reference::Reference,
    },
    voice::{
        assert_call_caps_admit, get_channel_node, get_user_voice_channel_in_server,
        get_voice_participant_identity, set_channel_node, set_user_moved_from_voice,
        set_user_moved_to_voice, sync_user_voice_permissions, UserVoiceChannel, VoiceClient,
    },
    Database, File, PartialMember, User,
};
use revolt_models::v0::{self, FieldsMember};

use revolt_permissions::{calculate_channel_permissions, calculate_server_permissions, ChannelPermission, UserPermission};
use revolt_result::{create_error, Result};
use rocket::{form::validate::Contains, serde::json::Json, State};
use validator::Validate;

/// # Edit Member
///
/// Edit a member by their id.
#[openapi(tag = "Server Members")]
#[patch("/<server_id>/members/<member_id>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    server_id: Reference<'_>,
    member_id: Reference<'_>,
    data: Json<v0::DataMemberEdit>,
) -> Result<Json<v0::Member>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Fetch server and member
    let mut server = server_id.as_server(db).await?;
    let target_user = member_id.as_user(db).await?;
    let mut member = member_id.as_member(db, &server.id).await?;

    // Fetch our currrent permissions
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    let permissions = calculate_server_permissions(&mut query).await;

    // Fetch target permissions
    let mut target_query = DatabasePermissionQuery::new(db, &target_user)
        .server(&server)
        .member(&member);
    let target_permissions = calculate_server_permissions(&mut target_query).await;

    // Check permissions in server
    if data.nickname.is_some() || data.remove.contains(&v0::FieldsMember::Nickname) {
        if user.id == member.id.user {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ChangeNickname)?;
        } else {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageNicknames)?;
        }
    }

    if data.pronouns.is_some() || data.remove.contains(&v0::FieldsMember::Pronouns) {
        if user.id != member.id.user {
            return Err(create_error!(InvalidOperation))
        }
    }

    if data.avatar.is_some() || data.remove.contains(&v0::FieldsMember::Avatar) {
        if user.id == member.id.user {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ChangeAvatar)?;
        } else if data.remove.contains(&v0::FieldsMember::Avatar) {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::RemoveAvatars)?;
        } else {
            return Err(create_error!(InvalidOperation))
        }
    }

    if data.roles.is_some() || data.remove.contains(&v0::FieldsMember::Roles) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::AssignRoles)?;
    }

    if data.timeout.is_some() || data.remove.contains(&v0::FieldsMember::Timeout) {
        if data.timeout.is_some() {
            if member.id.user == user.id {
                return Err(create_error!(CannotTimeoutYourself));
            }

            if target_permissions.has_channel_permission(ChannelPermission::TimeoutMembers) {
                return Err(create_error!(IsElevated));
            }
        }

        permissions.throw_if_lacking_channel_permission(ChannelPermission::TimeoutMembers)?;
    }

    if data.can_publish.is_some() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::MuteMembers)?;
    }

    if data.can_receive.is_some() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::DeafenMembers)?;
    }

    if data.voice_channel.is_some() && data.remove.contains(&FieldsMember::VoiceChannel) {
        return Err(create_error!(InvalidOperation));
    }

    if data.voice_channel.is_some() || data.remove.contains(&FieldsMember::VoiceChannel) {
        if !voice_client.is_enabled() {
            return Err(create_error!(LiveKitUnavailable));
        };

        if member.id.user != user.id {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
        }
    }

    let new_voice_channel = if let Some(new_channel) = &data.voice_channel {
        // ensure the channel we are moving them to is in the server and is a voice channel

        let channel = Reference::from_unchecked(new_channel)
            .as_channel(db)
            .await
            .map_err(|_| create_error!(UnknownChannel))?;

        if channel.server().is_none_or(|v| v != member.id.server) {
            Err(create_error!(UnknownChannel))?
        }

        let channel_permissions = calculate_channel_permissions(&mut query.clone().channel(&channel)).await;
        channel_permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

        if get_user_voice_channel_in_server(&target_user.id, &server.id)
            .await?
            .is_none()
        {
            Err(create_error!(NotConnected))?
        };

        // Enforce the same call-admission caps the join front door does (D12
        // video cap + T-20 MLS SFU coupling) against the DESTINATION channel,
        // for the user being moved. Without this a privileged move bypasses
        // caps a normal join is refused at — pushing a video call past its
        // ceiling, or dropping a non-enrolled ghost into a full E2EE call and
        // tripping every member's loud-downgrade banner (6.6 review finding 2,
        // re-opens audit CR-HIGH-2). Same server-written membership exemptions
        // as the join leg, and checked BEFORE any member mutation below so a
        // refusal leaves the member untouched.
        assert_call_caps_admit(db, &UserVoiceChannel::from_channel(&channel), &target_user.id)
            .await?;

        Some(channel)
    } else {
        None
    };

    // Resolve our ranking
    let our_ranking = query.get_member_rank().unwrap_or(i64::MIN);

    // Check that we have permissions to act against this member
    if member.id.user != user.id
        && member.get_ranking(query.server_ref().as_ref().unwrap()) <= our_ranking
    {
        return Err(create_error!(NotElevated));
    }

    // Check permissions against roles in diff
    if let Some(roles) = &data.roles {
        let current_roles = member.roles.iter().collect::<HashSet<&String>>();

        let new_roles = roles.iter().collect::<HashSet<&String>>();
        let added_roles: Vec<&&String> = new_roles.difference(&current_roles).collect();

        for role_id in added_roles {
            if let Some(role) = server.roles.remove(*role_id) {
                if role.rank <= our_ranking {
                    return Err(create_error!(NotElevated));
                }
            } else {
                return Err(create_error!(InvalidRole));
            }
        }
    }

    // Apply edits to the member object
    let v0::DataMemberEdit {
        nickname,
        pronouns,
        avatar,
        roles,
        timeout,
        remove,
        can_publish,
        can_receive,
        voice_channel: _,
    } = data;

    let mut partial = PartialMember {
        nickname,
        pronouns,
        roles,
        timeout,
        can_publish,
        can_receive,
        ..Default::default()
    };

    // 1. Remove fields from object
    if remove.contains(&v0::FieldsMember::Avatar) {
        if let Some(avatar) = &member.avatar {
            db.mark_attachment_as_deleted(&avatar.id).await?;
        }
    }

    // 2. Apply new avatar
    if let Some(avatar) = avatar {
        partial.avatar = Some(File::use_user_avatar(db, &avatar, &user.id, &user.id).await?);
    }

    member
        .update(db, partial, remove.clone().into_iter().map(Into::into).collect())
        .await?;

    if let Some(new_voice_channel) = new_voice_channel {
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            let old_node = get_channel_node(&channel).await?.unwrap();

            let new_node = match get_channel_node(new_voice_channel.id()).await? {
                Some(node) => node,
                None => {
                    set_channel_node(new_voice_channel.id(), &old_node).await?;
                    old_node.clone()
                }
            };

            let new_user_voice_channel = UserVoiceChannel::from_channel(&new_voice_channel);
            let old_user_voice_channel = UserVoiceChannel {
                id: channel.clone(),
                server_id: new_user_voice_channel.server_id.clone(),
            };

            set_user_moved_from_voice(&channel, &new_user_voice_channel, &target_user.id).await?;
            set_user_moved_to_voice(
                new_voice_channel.id(),
                &old_user_voice_channel,
                &target_user.id,
            )
            .await?;

            let mut query = perms(db, &target_user).channel(&new_voice_channel);
            let permissions = calculate_channel_permissions(&mut query).await;

            voice_client
                .create_room(&new_node, &new_voice_channel)
                .await?;

            // Preserve a device-qualified identity across the move: the
            // target's device suffix is recovered from the old channel's
            // ingress-maintained mapping (the server itself never knows
            // which device is in a call)
            let old_identity =
                get_voice_participant_identity(&channel, &target_user.id).await?;
            let device_id = old_identity
                .strip_prefix(&format!("{}:", target_user.id))
                .map(str::to_string);

            let token = voice_client
                .create_token(
                    &new_node,
                    db,
                    &target_user,
                    permissions,
                    &new_voice_channel,
                    device_id.as_deref(),
                )
                .await?;

            voice_client
                .remove_user(&old_node, &target_user.id, &channel)
                .await?;

            EventV1::UserMoveVoiceChannel {
                node: new_node,
                from: channel,
                to: new_voice_channel.id().to_string(),
                token,
            }
            .private(target_user.id.clone())
            .await;
        };
    } else if can_publish.is_some() || can_receive.is_some() || remove.contains(FieldsMember::CanPublish) || remove.contains(FieldsMember::CanReceive) {
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            let node = get_channel_node(&channel).await?.unwrap();
            let channel = Reference::from_unchecked(&channel).as_channel(db).await?;

            sync_user_voice_permissions(
                db,
                voice_client,
                &node,
                &user,
                &channel,
                Some(&server),
                None,
            )
            .await?;
        };
    };

    if remove.contains(&FieldsMember::VoiceChannel) {
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            let node = get_channel_node(&channel).await?.unwrap();

            // Disconnect the TARGET being removed, not the acting moderator
            // (matches the move branch above; the earlier `user.id` here kicked
            // the moderator out of their own call — 6.6 review finding 8).
            voice_client
                .remove_user(&node, &target_user.id, &channel)
                .await?;
        };
    }

    Ok(Json(member.into()))
}

// These tests seed the process-global redis_kiss connection, so (like the
// routes::mls suite) they are only reliable one-per-process — nextest, the
// repo's canonical runner, isolates them; under plain `cargo test` run with
// `--test-threads=1`.
#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, set_channel_node, update_voice_state,
            UserVoiceChannel, MAX_VIDEO_PARTICIPANTS,
        },
        Channel, Member, MlsGroup, MlsGroupCreateOutcome, MlsMemberDevice, Server, User,
        MAX_MLS_GROUP_MEMBERS,
    };
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};

    async fn voice_channel(harness: &TestHarness, server: &Server, name: &str) -> Channel {
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
            },
            true,
        )
        .await
        .expect("voice channel")
    }

    /// Seed an open MLS group on `channel_id` with the given members.
    async fn seed_open_group(
        harness: &TestHarness,
        seed: u8,
        channel_id: &str,
        members: Vec<MlsMemberDevice>,
    ) {
        let outcome = harness
            .db
            .create_mls_group(
                &MlsGroup {
                    id: format!("{seed:02x}").repeat(32),
                    channel_id: channel_id.to_string(),
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
    }

    fn synthetic_members(n: usize) -> Vec<MlsMemberDevice> {
        (0..n)
            .map(|i| MlsMemberDevice {
                user_id: format!("0SYNTHETICUSER{i:012}"),
                device_id: format!("{i:032x}"),
            })
            .collect()
    }

    /// PATCH the target member to move them into `dest`, acting as `mod_token`.
    async fn move_member<'a>(
        harness: &'a TestHarness,
        mod_token: &str,
        server_id: &str,
        target_id: &str,
        dest_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .patch(format!("/servers/{server_id}/members/{target_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", mod_token.to_string()))
            .body(serde_json::json!({ "voice_channel": dest_id }).to_string())
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
            "the move must be refused with the distinguishable {error_type} error"
        );
    }

    #[rocket::async_test]
    async fn move_into_full_mls_call_refused_and_member_exempt() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // moderator = server owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target being moved
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let dest_full = voice_channel(&harness, &server, "DestFull").await;
        let dest_member = voice_channel(&harness, &server, "DestMember").await;

        // Target is connected in the source channel (the move precondition),
        // and the source has a node so the exemption path can proceed past the
        // caps into the (unreachable-in-test) LiveKit machinery.
        let source_uvc = UserVoiceChannel::from_channel(&source);
        create_voice_state(&source_uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        set_channel_node(source.id(), "worldwide").await.expect("node");

        // Destination A: open MLS group at the cap, target NOT a member.
        seed_open_group(
            &harness,
            0x51,
            dest_full.id(),
            synthetic_members(MAX_MLS_GROUP_MEMBERS),
        )
        .await;
        // Destination B: same, but target IS a member (any device = exempt).
        let mut with_target = synthetic_members(MAX_MLS_GROUP_MEMBERS - 1);
        with_target.push(MlsMemberDevice {
            user_id: user_b.id.clone(),
            device_id: "bb".repeat(16),
        });
        seed_open_group(&harness, 0x52, dest_member.id(), with_target).await;

        // Moderator moves the non-member target into the full E2EE call → the
        // privileged door is refused with the SAME 409 the join front door
        // raises (6.6 finding 2 — CR-HIGH-2 must not re-open here).
        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            dest_full.id(),
        )
        .await;
        assert_refused(response, "MlsCallFull").await;

        // Moving an EXISTING member of the destination group is exempt — the
        // cap does not fire (the move proceeds past the caps; it then fails on
        // the unreachable LiveKit node, which is NOT a Conflict).
        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            dest_member.id(),
        )
        .await;
        assert_ne!(
            response.status(),
            Status::Conflict,
            "an existing member's move must not be cap-refused"
        );

        delete_channel_voice_state(&source_uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    #[rocket::async_test]
    async fn move_into_full_video_call_refused() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let dest = voice_channel(&harness, &server, "Dest").await;

        let source_uvc = UserVoiceChannel::from_channel(&source);
        create_voice_state(&source_uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");

        // Destination is a video-active call at the cap (target not present).
        let dest_uvc = UserVoiceChannel::from_channel(&dest);
        let synthetic: Vec<String> = (0..MAX_VIDEO_PARTICIPANTS)
            .map(|i| format!("0SYNTHVIDEOUSER{i:011}"))
            .collect();
        for uid in &synthetic {
            create_voice_state(&dest_uvc, uid, Timestamp::now_utc())
                .await
                .expect("dest state");
        }
        update_voice_state(
            &dest_uvc,
            &synthetic[0],
            &v0::PartialUserVoiceState {
                camera: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("camera flag");

        // Moderator moves the target into the full video call → 409.
        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            dest.id(),
        )
        .await;
        assert_refused(response, "VideoCallFull").await;

        delete_channel_voice_state(&source_uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup source");
        delete_channel_voice_state(&dest_uvc, &synthetic)
            .await
            .expect("cleanup dest");
    }
}
