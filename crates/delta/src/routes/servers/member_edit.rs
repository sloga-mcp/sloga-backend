use std::collections::HashSet;

use revolt_database::{
    events::client::EventV1,
    util::{
        name_filter::contains_blocked_slur,
        permissions::{perms, DatabasePermissionQuery},
        reference::Reference,
    },
    voice::{
        assert_call_caps_admit, get_channel_node, get_user_voice_channel_in_server,
        get_voice_channel_members, get_voice_participant_identity, set_channel_node,
        set_user_moved_from_voice, set_user_moved_to_voice, sync_user_voice_permissions,
        UserVoiceChannel, VoiceClient,
    },
    Database, E2EEIdentity, File, PartialMember, Session, User,
};
use revolt_models::v0::{self, FieldsMember};

use revolt_permissions::{calculate_channel_permissions, calculate_server_permissions, ChannelPermission, UserPermission};
use revolt_result::{create_error, ErrorType, Result};
use rocket::{form::validate::Contains, serde::json::Json, State};
use validator::Validate;

/// Public LiveKit URL of `node`, carried on `UserMoveVoiceChannel` so the moved
/// client connects with the fresh token straight away. Same source as the `url`
/// `join_call` returns for a node: the `hosts.livekit` entry. `None` for a node
/// with no public URL configured.
fn move_event_url(config: &revolt_config::Settings, node: &str) -> Option<String> {
    config.hosts.livekit.get(node).cloned()
}

/// The device suffix of a moved participant's LiveKit identity (`user:device`),
/// or `None` when the move takes the bare-identity path.
///
/// With media E2EE switched off, `join_call` admits only bare identities (a
/// device claim is refused `FeatureDisabled` by `require_media_e2ee_enabled`),
/// so a move never mints a device-qualified token then either: it falls back
/// to the bare identity the target could join with themselves.
///
/// An identity ending in `:` yields `Some("")`, which no identity row matches,
/// so it fails closed below rather than being treated as bare.
fn qualified_move_device<'a>(
    identity: &'a str,
    user_id: &str,
    media_e2ee_enabled: bool,
) -> Option<&'a str> {
    if !media_e2ee_enabled {
        return None;
    }

    identity.strip_prefix(user_id)?.strip_prefix(':')
}

/// Where a move's `UserMoveVoiceChannel` event goes, and whether it carries a
/// token.
#[derive(Debug, PartialEq, Eq)]
enum MoveDelivery {
    /// Mint the token for `device_id` and publish only to `session_id`, the
    /// session bound to that device.
    Session {
        session_id: String,
        device_id: String,
    },
    /// Mint the bare-identity token and publish to every session of the user.
    /// Any session of the user could get the same token from `join_call`.
    User,
    /// Mint nothing and publish without a token to every session of the user.
    /// The client falls back to `join_call`, which enforces device binding.
    UserNoToken,
}

/// The topic a move's `UserMoveVoiceChannel` event is published on.
#[derive(Debug, PartialEq, Eq)]
enum MoveTopic<'a> {
    /// One session only (`EventV1::private_session`).
    Session(&'a str),
    /// Every session of the target (`EventV1::private`).
    User,
}

/// What the move route does with a [`MoveDelivery`]: the token it mints and
/// the topic it publishes on. The route branches on nothing else.
#[derive(Debug, PartialEq, Eq)]
struct MoveTokenPlan<'a> {
    /// `None`: mint no token. `Some(None)`: mint the bare-identity token.
    /// `Some(Some(device))`: mint the token for `user:device`.
    mint: Option<Option<&'a str>>,
    topic: MoveTopic<'a>,
}

/// Plan the token and topic of a move. A device-qualified token is minted
/// only when the event goes to that device's bound session alone; every
/// user-wide delivery carries a bare token or none.
fn move_token_plan(delivery: &MoveDelivery) -> MoveTokenPlan<'_> {
    match delivery {
        MoveDelivery::Session {
            session_id,
            device_id,
        } => MoveTokenPlan {
            mint: Some(Some(device_id.as_str())),
            topic: MoveTopic::Session(session_id.as_str()),
        },
        MoveDelivery::User => MoveTokenPlan {
            mint: Some(None),
            topic: MoveTopic::User,
        },
        MoveDelivery::UserNoToken => MoveTokenPlan {
            mint: None,
            topic: MoveTopic::User,
        },
    }
}

/// Decide the delivery of a move's event.
///
/// `device` is the result of [`qualified_move_device`]. `bound_session` is the
/// `last_session_id` of the target's E2EE identity row for that device, or
/// `None` when there is no row. Revoking a device deletes its row
/// (`E2EEIdentity::revoke_device`), so a revoked device arrives here as `None`.
///
/// A device-qualified token lets its holder act as that device on the SFU, so
/// it goes only to the session `assert_bound_session` would accept for the
/// device. Sent to every session of the user, a stolen web session would get
/// a token `join_call` refuses it.
///
/// An empty device suffix or session id fails closed to `UserNoToken`.
fn move_event_delivery(device: Option<&str>, bound_session: Option<&str>) -> MoveDelivery {
    match (device, bound_session) {
        (None, _) => MoveDelivery::User,
        (Some(device_id), Some(session_id)) if !device_id.is_empty() && !session_id.is_empty() => {
            MoveDelivery::Session {
                session_id: session_id.to_string(),
                device_id: device_id.to_string(),
            }
        }
        (Some(_), _) => MoveDelivery::UserNoToken,
    }
}

/// The target's E2EE identity row for `device_id`, or `None` if the device is
/// not registered (never was, or was revoked). Other errors propagate.
async fn fetch_device_identity(
    db: &Database,
    user_id: &str,
    device_id: &str,
) -> Result<Option<E2EEIdentity>> {
    match db.fetch_e2ee_identity(user_id, device_id).await {
        Ok(identity) => Ok(Some(identity)),
        Err(error) if matches!(error.error_type, ErrorType::NotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Refuse a move or disconnect when the target's voice channel changed after
/// the permission checks ran against `checked`. `current` is a fresh read.
///
/// A target who has since left is `NotConnected`, as a move of someone not in
/// voice already is. Any other change (a different channel, or joining one
/// after the checks saw them out of voice) is `InvalidOperation`, the error
/// this route already uses for a request that no longer fits the member's
/// state.
fn assert_voice_channel_unchanged(checked: Option<&str>, current: Option<&str>) -> Result<()> {
    if checked == current {
        return Ok(());
    }

    match current {
        None => Err(create_error!(NotConnected)),
        Some(_) => Err(create_error!(InvalidOperation)),
    }
}

/// Whether an edit can change the member's effective voice permissions, and so
/// requires their LiveKit participant to be re-synced afterwards.
///
/// The server-mute / server-deafen overrides (`can_publish`, `can_receive`) are
/// the obvious case, but they are not the only one:
///
/// - `roles` feeds `get_our_server_role_overrides` / `get_our_channel_role_overrides`,
///   so granting or stripping a role moves Speak, Listen and Video.
/// - `timeout` restricts the member down to `ALLOW_IN_TIMEOUT` (ViewChannel +
///   ReadMessageHistory), dropping Speak, Listen and Video entirely.
///
/// Neither used to trigger a sync, so stripping a voice-granting role or timing
/// a member out left the SFU honouring the stale grant until something else
/// happened to sync the channel.
fn edit_affects_voice_permissions(data: &v0::DataMemberEdit) -> bool {
    data.can_publish.is_some()
        || data.can_receive.is_some()
        || data.roles.is_some()
        || data.timeout.is_some()
        || data.remove.iter().any(|field| {
            matches!(
                field,
                FieldsMember::CanPublish
                    | FieldsMember::CanReceive
                    | FieldsMember::Roles
                    | FieldsMember::Timeout
            )
        })
}

/// # Edit Member
///
/// Edit a member by their id.
#[openapi(tag = "Server Members")]
#[patch("/<server_id>/members/<member_id>", data = "<data>")]
pub async fn edit(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    // Optional because bots authenticate with `x-bot-token` and have no
    // session; every edit that does not self-move a device-qualified
    // participant ignores it.
    session: Option<Session>,
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

    // A nickname is the display name everyone in the server reads, so it gets
    // the same slur filter as usernames and display names.
    if let Some(nickname) = &data.nickname {
        if contains_blocked_slur(nickname) {
            return Err(create_error!(DisallowedName));
        }
    }

    // Fetch server and member
    let server = server_id.as_server(db).await?;
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

    // Applying AND lifting a server mute are both moderation actions, so both
    // need MuteMembers. The `remove` shape resets the field to its default
    // (`true`) just as surely as `can_publish: true` does, and it used to pass
    // through unchecked.
    //
    // The permission alone is not enough, because the rank check below is
    // SKIPPED for a self-edit: a moderator who holds MuteMembers and has been
    // server-muted would otherwise lift their own mute. Nobody moderates
    // themselves here, in either direction — same rule the timeout block above
    // applies with `CannotTimeoutYourself`.
    if data.can_publish.is_some() || data.remove.contains(&FieldsMember::CanPublish) {
        if member.id.user == user.id {
            return Err(create_error!(InvalidOperation));
        }

        permissions.throw_if_lacking_channel_permission(ChannelPermission::MuteMembers)?;
    }

    if data.can_receive.is_some() || data.remove.contains(&FieldsMember::CanReceive) {
        if member.id.user == user.id {
            return Err(create_error!(InvalidOperation));
        }

        permissions.throw_if_lacking_channel_permission(ChannelPermission::DeafenMembers)?;
    }

    // `can_publish: false` alongside `remove: ["CanPublish"]` asks to set and
    // clear one field in a single edit. The two drivers disagree about the
    // result (Mongo rejects a conflicting $set/$unset pair outright; the
    // reference driver applies the remove first and succeeds), and the event
    // that would go out contradicts the response body. Refuse it the same way
    // the `voice_channel` collision below is refused.
    if (data.can_publish.is_some() && data.remove.contains(&FieldsMember::CanPublish))
        || (data.can_receive.is_some() && data.remove.contains(&FieldsMember::CanReceive))
    {
        return Err(create_error!(InvalidOperation));
    }

    if data.voice_channel.is_some() && data.remove.contains(&FieldsMember::VoiceChannel) {
        return Err(create_error!(InvalidOperation));
    }

    // Resolve our ranking
    let our_ranking = query.get_member_rank().unwrap_or(i64::MIN);

    // Check that we have permissions to act against this member. Platform
    // staff resolve no member rank (`i64::MIN`), which now ties with the
    // owner's, so they are exempt here to keep the reach they already had.
    //
    // Checked BEFORE any voice lookup below: a moderator who does not outrank
    // the target must not learn, from which error comes back, whether the
    // target is in voice, where, or which channels the target can see.
    if member.id.user != user.id
        && !user.privileged
        && member.get_ranking(query.server_ref().as_ref().unwrap()) <= our_ranking
    {
        return Err(create_error!(NotElevated));
    }

    let changes_voice_channel =
        data.voice_channel.is_some() || data.remove.contains(&FieldsMember::VoiceChannel);

    // The voice channel the target is in right now, in this server.
    let source_voice_channel = if changes_voice_channel {
        if !voice_client.is_enabled() {
            return Err(create_error!(LiveKitUnavailable));
        };

        get_user_voice_channel_in_server(&target_user.id, &server.id).await?
    } else {
        None
    };

    // Moving or disconnecting someone else takes MoveMembers on the channel
    // they are taken OUT of, so a channel override can scope it. With no
    // source channel (not in voice, or the channel has since been deleted)
    // there is nothing to scope to and the server-level permission applies.
    if changes_voice_channel && member.id.user != user.id {
        let source_channel = match &source_voice_channel {
            Some(source_id) => match Reference::from_unchecked(source_id).as_channel(db).await {
                Ok(channel) => Some(channel),
                Err(error) if matches!(error.error_type, ErrorType::NotFound) => None,
                Err(error) => return Err(error),
            },
            None => None,
        };

        match &source_channel {
            Some(source_channel) => {
                calculate_channel_permissions(&mut query.clone().channel(source_channel))
                    .await
                    .throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
            }
            None => {
                permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
            }
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

        let Some(max_users) = channel.voice().map(|voice| voice.max_users) else {
            return Err(create_error!(NotAVoiceChannel));
        };

        let channel_permissions = calculate_channel_permissions(&mut query.clone().channel(&channel)).await;
        channel_permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

        // ...and on the channel they are moved INTO.
        if member.id.user != user.id {
            channel_permissions
                .throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
        }

        let Some(source_id) = &source_voice_channel else {
            return Err(create_error!(NotConnected));
        };

        if source_id == channel.id() {
            return Err(create_error!(InvalidOperation));
        }

        let user_voice_channel = UserVoiceChannel::from_channel(&channel);

        if member.id.user != user.id {
            // The target need not hold Connect (a moderator may move someone
            // into a channel they could not join, e.g. a timeout channel), but
            // must be able to see it. The mover's own ViewChannel is implied
            // by the Connect check above, so a MissingPermission ViewChannel
            // here always means the target's.
            calculate_channel_permissions(&mut target_query.clone().channel(&channel))
                .await
                .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
        } else if get_voice_channel_members(&user_voice_channel)
            .await?
            .zip(max_users)
            .is_some_and(|(members, max_users)| members.len() >= max_users)
            && !channel_permissions.has(ChannelPermission::ManageChannel as u64)
        {
            // Moving yourself is a join: same user limit and ManageChannel
            // exemption as `join_call`. A moderator move is not held to it.
            return Err(create_error!(CannotJoinCall));
        }

        // Enforce the same call-admission caps the join front door does (D12
        // video cap + T-20 MLS SFU coupling) against the DESTINATION channel,
        // for the user being moved. Without this a privileged move bypasses
        // caps a normal join is refused at — pushing a video call past its
        // ceiling, or dropping a non-enrolled ghost into a full E2EE call and
        // tripping every member's loud-downgrade banner (6.6 review finding 2,
        // re-opens audit CR-HIGH-2). Same server-written membership exemptions
        // as the join leg, and checked BEFORE any member mutation below so a
        // refusal leaves the member untouched.
        assert_call_caps_admit(db, &user_voice_channel, &target_user.id).await?;

        Some(channel)
    } else {
        None
    };

    // Check permissions against roles in diff
    if let Some(roles) = &data.roles {
        let current_roles = member.roles.iter().collect::<HashSet<&String>>();

        let new_roles = roles.iter().collect::<HashSet<&String>>();
        let added_roles: Vec<&&String> = new_roles.difference(&current_roles).collect();

        for role_id in added_roles {
            // `get`, never `remove`: this same `server` is handed to the voice
            // permission sync below, and taking the role out of the local copy
            // made `get_our_server_role_overrides` skip the role that was just
            // granted — the sync would compute, and push to LiveKit, the
            // permissions the member had BEFORE the edit.
            if let Some(role) = server.roles.get(*role_id) {
                if role.rank <= our_ranking {
                    return Err(create_error!(NotElevated));
                }
            } else {
                return Err(create_error!(InvalidRole));
            }
        }
    }

    // Decide this before `data` is destructured below.
    let affects_voice_permissions = edit_affects_voice_permissions(&data);

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

    // Every voice check above (MoveMembers on the source, the same-channel
    // refusal) was made against `source_voice_channel`. Re-read it here, before
    // the first side effect, and refuse if the target has since left or hopped
    // channels: acting on the channel they are in NOW would move or kick them
    // out of a channel nobody checked. The actions below then use the checked
    // id instead of reading it a third time.
    //
    // The source's node is resolved here too, so a move out of a channel whose
    // node mapping is gone is refused before anything is written, rather than
    // panicking on it halfway through.
    let source_node = if changes_voice_channel {
        let current_voice_channel =
            get_user_voice_channel_in_server(&target_user.id, &server.id).await?;
        assert_voice_channel_unchanged(
            source_voice_channel.as_deref(),
            current_voice_channel.as_deref(),
        )?;

        match &source_voice_channel {
            Some(source_id) => {
                let node = get_channel_node(source_id).await?;
                if node.is_none() && new_voice_channel.is_some() {
                    return Err(create_error!(NotConnected));
                }
                node
            }
            None => None,
        }
    } else {
        None
    };

    // Which LiveKit identity the move may mint a token for, and who receives
    // it. Resolved before the first side effect, so the refusals below leave
    // the member untouched. The target's device suffix comes from the source
    // channel's ingress-maintained identity mapping (the server itself never
    // knows which device is in a call).
    let move_delivery = match (&new_voice_channel, &source_voice_channel) {
        (Some(_), Some(source_id)) => {
            let identity = get_voice_participant_identity(source_id, &target_user.id).await?;
            let media_e2ee_enabled = crate::routes::mls::require_media_e2ee_enabled()
                .await
                .is_ok();
            let device_id = qualified_move_device(&identity, &target_user.id, media_e2ee_enabled)
                .map(str::to_string);

            let identity_row = match &device_id {
                Some(device_id) => fetch_device_identity(db, &target_user.id, device_id).await?,
                None => None,
            };

            // Moving yourself is a join. For a device-qualified participant
            // it must come from the session bound to that device, as
            // `join_call` requires (`assert_device_bound_session`): otherwise
            // a stolen web session could move its victim and act as the
            // victim's device. The errors are the ones `join_call` returns.
            // A bot has no session, and cannot hold a device identity.
            if member.id.user == user.id && device_id.is_some() {
                let session = session
                    .as_ref()
                    .filter(|session| session.user_id == user.id)
                    .ok_or_else(|| create_error!(NotAuthenticated))?;

                identity_row
                    .as_ref()
                    .ok_or_else(|| {
                        create_error!(FailedValidation {
                            error: "joining device is not registered".to_string()
                        })
                    })?
                    .assert_bound_session(&session.id)?;
            }

            let delivery = move_event_delivery(
                device_id.as_deref(),
                identity_row
                    .as_ref()
                    .map(|identity| identity.last_session_id.as_str()),
            );

            Some(delivery)
        }
        _ => None,
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
        // All three are `Some` here: a move with no source is refused
        // NotConnected in the destination checks, one with no source node just
        // above, and the delivery is resolved for every move with a source.
        if let (Some(channel), Some(old_node), Some(delivery)) = (
            source_voice_channel.clone(),
            source_node.clone(),
            move_delivery,
        ) {
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

            // Preserve a device-qualified identity across the move, but only
            // for a delivery that reaches that device's bound session alone.
            // The mint and the topic below come from the plan and nothing else.
            let plan = move_token_plan(&delivery);
            let token = match plan.mint {
                None => None,
                Some(token_device) => Some(
                    voice_client
                        .create_token(
                            &new_node,
                            db,
                            &target_user,
                            permissions,
                            &new_voice_channel,
                            token_device,
                        )
                        .await?,
                ),
            };

            // Remote-control release hook (plan §1: the moderator voice-move
            // calls `remove_user` directly, bypassing
            // `remove_user_from_voice_channel`, and additionally re-tokens
            // the target into a DIFFERENT room while any grant stays keyed
            // to the old channel — so it must release explicitly here).
            revolt_database::voice::remote_control::release_remote_control_for_user(
                db,
                voice_client,
                &old_user_voice_channel,
                &target_user.id,
                "revoked_by_moderator",
                // The participant is still in the old room right now — the
                // removal happens below and can fail, so revoke actively.
                false,
            )
            .await;

            voice_client
                .remove_user(&old_node, &target_user.id, &channel)
                .await?;

            let url = move_event_url(&revolt_config::config().await, &new_node);

            let event = EventV1::UserMoveVoiceChannel {
                node: new_node,
                from: channel,
                to: new_voice_channel.id().to_string(),
                token,
                url,
            };

            match plan.topic {
                MoveTopic::Session(session_id) => {
                    event.private_session(session_id.to_string()).await
                }
                MoveTopic::User => event.private(target_user.id.clone()).await,
            }
        };
    } else if affects_voice_permissions && !remove.contains(&FieldsMember::VoiceChannel) {
        // Skipped when the member is being disconnected outright just below —
        // syncing a participant we are about to evict is pointless, and a
        // failing sync would abort the request before the eviction ran.
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            // With no node mapping there is no room to sync, so the sync is
            // skipped (the member edit above has already landed).
            if let Some(node) = get_channel_node(&channel).await? {
                let channel = Reference::from_unchecked(&channel).as_channel(db).await?;

                // Sync the TARGET being edited, not the acting moderator.
                // Passing `&user` here synced the moderator's own participant,
                // and since `sync_user_voice_permissions` early-returns for a
                // user with no voice state it usually did nothing at all —
                // server-mute and server-deafen never reached the target's SFU
                // participant.
                sync_user_voice_permissions(
                    db,
                    voice_client,
                    &node,
                    &target_user,
                    &channel,
                    Some(&server),
                    None,
                )
                .await?;
            }
        };
    };

    if remove.contains(&FieldsMember::VoiceChannel) {
        if let Some(channel) = source_voice_channel {
            // Remote-control release hook (plan §1: the moderator disconnect
            // also calls `remove_user` directly and would race a
            // webhook-only hook).
            revolt_database::voice::remote_control::release_remote_control_for_user(
                db,
                voice_client,
                &UserVoiceChannel {
                    id: channel.clone(),
                    server_id: Some(server.id.clone()),
                },
                &target_user.id,
                "revoked_by_moderator",
                // Still connected at this point; the disconnect is below.
                false,
            )
            .await;

            // Disconnect the TARGET being removed, not the acting moderator
            // (matches the move branch above; the earlier `user.id` here kicked
            // the moderator out of their own call — 6.6 review finding 8).
            //
            // With no node mapping there is no room to kick them from, so
            // there is nothing left to do (it used to panic here instead).
            if let Some(node) = source_node {
                voice_client
                    .remove_user(&node, &target_user.id, &channel)
                    .await?;
            }
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
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        events::client::EventV1,
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            delete_voice_participant_identity, get_user_moved_from_voice, get_voice_state,
            set_channel_node, set_voice_participant_identity, update_voice_state, UserVoiceChannel,
            MAX_VIDEO_PARTICIPANTS,
        },
        Bot, Channel, E2EEIdentity, E2EESignedKey, Member, MlsGroup, MlsGroupCreateOutcome,
        MlsMemberDevice, PartialChannel, PartialMember, PartialRole, PartialServer, Role, Server,
        User, MAX_MLS_GROUP_MEMBERS,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{ContentType, Header, Status};

    async fn voice_channel(harness: &TestHarness, server: &Server, name: &str) -> Channel {
        limited_voice_channel(harness, server, name, None).await
    }

    async fn limited_voice_channel(
        harness: &TestHarness,
        server: &Server,
        name: &str,
        max_users: Option<usize>,
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
                    max_users,
                    disabled: false,
                }),
                announcement: None,
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

    #[test]
    fn move_into_full_mls_call_refused_and_member_exempt() {
        crate::util::test::rt().block_on(move_into_full_mls_call_refused_and_member_exempt_case())
    }

    async fn move_into_full_mls_call_refused_and_member_exempt_case() {
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

    #[test]
    fn move_into_full_video_call_refused() {
        crate::util::test::rt().block_on(move_into_full_video_call_refused_case())
    }

    async fn move_into_full_video_call_refused_case() {
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

    // ---- who may move whom, and where ------------------------------------
    //
    // A move that clears every check runs into `create_room` on the source's
    // node. The fixture pins that to `ABSENT_NODE`, so it fails fast with
    // `UnknownNode`: that error is the observable for "got past every
    // permission and destination check", and is asserted exactly rather than
    // as "not a 403".

    struct MoveFixture {
        harness: TestHarness,
        server: Server,
        moderator: User,
        mod_token: String,
        /// Rank-1 role that grants MoveMembers server-wide (or nothing, see
        /// `move_fixture`).
        mod_role: Role,
        target: User,
        target_token: String,
        source: Channel,
        dest: Channel,
        source_uvc: UserVoiceChannel,
    }

    impl MoveFixture {
        async fn cleanup(&self) {
            delete_channel_voice_state(&self.source_uvc, &[self.target.id.clone()])
                .await
                .expect("cleanup source");
        }
    }

    /// A role with explicit rank and permissions. `Role::create` derives the
    /// rank from the (stale) server passed in, so it is set here instead.
    async fn ranked_role(harness: &TestHarness, server: &Server, rank: i64, allow: u64) -> Role {
        let mut role = harness
            .new_role(
                server,
                rank,
                Some(OverrideField {
                    a: allow as i64,
                    d: 0,
                }),
            )
            .await;
        role.update(
            &harness.db,
            &server.id,
            PartialRole {
                rank: Some(rank),
                ..Default::default()
            },
            Vec::new(),
        )
        .await
        .expect("role rank");
        role
    }

    async fn give_role(harness: &TestHarness, server: &Server, user: &User, role: &Role) {
        let mut member = harness
            .db
            .fetch_member(&server.id, &user.id)
            .await
            .expect("member read");
        let mut roles = member.roles.clone();
        roles.push(role.id.clone());
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(roles),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("assign role");
    }

    async fn channel_override(
        harness: &TestHarness,
        channel: &Channel,
        role: &Role,
        a: u64,
        d: u64,
    ) {
        // Through `update`, not `set_role_permission`: the reference driver's
        // `set_channel_role_permission` only replaces an EXISTING role entry
        // and returns NotFound for a new one.
        let mut channel = harness
            .db
            .fetch_channel(channel.id())
            .await
            .expect("channel read");
        let Channel::TextChannel {
            role_permissions, ..
        } = &channel
        else {
            panic!("voice channels are text channels with voice info");
        };
        let mut role_permissions = role_permissions.clone();
        role_permissions.insert(
            role.id.clone(),
            OverrideField {
                a: a as i64,
                d: d as i64,
            },
        );
        channel
            .update(
                &harness.db,
                PartialChannel {
                    role_permissions: Some(role_permissions),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("channel override");
    }

    /// Owner, a moderator holding a rank-1 role (granting MoveMembers
    /// server-wide when `server_move_members`), and a plain member connected
    /// in `source`.
    async fn move_fixture(server_move_members: bool) -> MoveFixture {
        let harness = TestHarness::new().await;
        let (_a, _session_a, owner) = harness.new_user().await;
        let (_m, session_m, moderator) = harness.new_user().await;
        let (_t, session_t, target) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&owner).await;

        for user in [&moderator, &target] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        let allow = if server_move_members {
            ChannelPermission::MoveMembers as u64
        } else {
            0
        };
        let mod_role = ranked_role(&harness, &server, 1, allow).await;
        give_role(&harness, &server, &moderator, &mod_role).await;

        let source = voice_channel(&harness, &server, "Source").await;
        let dest = voice_channel(&harness, &server, "Dest").await;

        let source_uvc = UserVoiceChannel::from_channel(&source);
        create_voice_state(&source_uvc, &target.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        set_channel_node(source.id(), ABSENT_NODE)
            .await
            .expect("node");

        MoveFixture {
            harness,
            server,
            moderator,
            mod_token: session_m.token,
            mod_role,
            target,
            target_token: session_t.token,
            source,
            dest,
            source_uvc,
        }
    }

    async fn error_of(
        response: rocket::local::asynchronous::LocalResponse<'_>,
    ) -> (Status, revolt_result::ErrorType) {
        let status = response.status();
        let error: revolt_result::Error = response.into_json().await.expect("error body");
        (status, error.error_type)
    }

    async fn assert_missing_permission(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        permission: ChannelPermission,
    ) {
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Forbidden, "{error:?}");
        assert!(
            matches!(
                &error,
                revolt_result::ErrorType::MissingPermission { permission: p }
                    if *p == permission.to_string()
            ),
            "expected MissingPermission {}, got {:?}",
            permission,
            error
        );
    }

    /// Cleared every check and reached the (absent) LiveKit node.
    async fn assert_reached_livekit(response: rocket::local::asynchronous::LocalResponse<'_>) {
        let (status, error) = error_of(response).await;
        assert!(
            matches!(error, revolt_result::ErrorType::UnknownNode),
            "the move must clear every check and only fail at the absent \
             LiveKit node, got {} {:?}",
            status,
            error
        );
    }

    #[test]
    fn move_needs_move_members_on_the_source_channel() {
        crate::util::test::rt().block_on(move_needs_move_members_on_the_source_channel_case())
    }

    async fn move_needs_move_members_on_the_source_channel_case() {
        let f = move_fixture(true).await;
        channel_override(
            &f.harness,
            &f.source,
            &f.mod_role,
            0,
            ChannelPermission::MoveMembers as u64,
        )
        .await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_missing_permission(response, ChannelPermission::MoveMembers).await;

        f.cleanup().await;
    }

    #[test]
    fn move_needs_move_members_on_the_destination_channel() {
        crate::util::test::rt().block_on(move_needs_move_members_on_the_destination_channel_case())
    }

    async fn move_needs_move_members_on_the_destination_channel_case() {
        let f = move_fixture(true).await;
        channel_override(
            &f.harness,
            &f.dest,
            &f.mod_role,
            0,
            ChannelPermission::MoveMembers as u64,
        )
        .await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_missing_permission(response, ChannelPermission::MoveMembers).await;

        f.cleanup().await;
    }

    #[test]
    fn channel_scoped_move_members_is_enough_to_move() {
        crate::util::test::rt().block_on(channel_scoped_move_members_is_enough_to_move_case())
    }

    /// The per-channel check replaces the server-level one: a moderator whose
    /// MoveMembers comes only from overrides on the two channels involved may
    /// move, and one lacking it everywhere may not.
    async fn channel_scoped_move_members_is_enough_to_move_case() {
        let f = move_fixture(false).await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_missing_permission(response, ChannelPermission::MoveMembers).await;

        for channel in [&f.source, &f.dest] {
            channel_override(
                &f.harness,
                channel,
                &f.mod_role,
                ChannelPermission::MoveMembers as u64,
                0,
            )
            .await;
        }

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        f.cleanup().await;
    }

    #[test]
    fn move_needs_the_mover_to_outrank_the_target() {
        crate::util::test::rt().block_on(move_needs_the_mover_to_outrank_the_target_case())
    }

    async fn move_needs_the_mover_to_outrank_the_target_case() {
        let f = move_fixture(true).await;
        let senior = ranked_role(&f.harness, &f.server, 0, 0).await;
        give_role(&f.harness, &f.server, &f.target, &senior).await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Forbidden);
        assert!(
            matches!(error, revolt_result::ErrorType::NotElevated),
            "a move of a higher-ranked member must fail on rank, got {:?}",
            error
        );

        f.cleanup().await;
    }

    #[test]
    fn move_into_another_servers_channel_is_refused() {
        crate::util::test::rt().block_on(move_into_another_servers_channel_is_refused_case())
    }

    async fn move_into_another_servers_channel_is_refused_case() {
        let f = move_fixture(true).await;
        // The moderator owns this one, so every permission there is theirs.
        let (elsewhere, _channels) = f.harness.new_server(&f.moderator).await;
        let foreign = voice_channel(&f.harness, &elsewhere, "Foreign").await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            foreign.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::NotFound);
        assert!(
            matches!(error, revolt_result::ErrorType::UnknownChannel),
            "{:?}",
            error
        );

        f.cleanup().await;
    }

    #[test]
    fn move_into_a_text_channel_is_refused() {
        crate::util::test::rt().block_on(move_into_a_text_channel_is_refused_case())
    }

    async fn move_into_a_text_channel_is_refused_case() {
        let f = move_fixture(true).await;
        let text = f.harness.new_channel(&f.server).await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            text.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest);
        assert!(
            matches!(error, revolt_result::ErrorType::NotAVoiceChannel),
            "{:?}",
            error
        );

        f.cleanup().await;
    }

    #[test]
    fn move_into_the_current_channel_is_refused() {
        crate::util::test::rt().block_on(move_into_the_current_channel_is_refused_case())
    }

    async fn move_into_the_current_channel_is_refused_case() {
        let f = move_fixture(true).await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.source.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest);
        assert!(
            matches!(error, revolt_result::ErrorType::InvalidOperation),
            "{:?}",
            error
        );

        f.cleanup().await;
    }

    #[test]
    fn move_needs_the_target_to_see_the_destination() {
        crate::util::test::rt().block_on(move_needs_the_target_to_see_the_destination_case())
    }

    async fn move_needs_the_target_to_see_the_destination_case() {
        let f = move_fixture(true).await;
        let hidden = ranked_role(&f.harness, &f.server, 2, 0).await;
        give_role(&f.harness, &f.server, &f.target, &hidden).await;
        channel_override(
            &f.harness,
            &f.dest,
            &hidden,
            0,
            ChannelPermission::ViewChannel as u64,
        )
        .await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_missing_permission(response, ChannelPermission::ViewChannel).await;

        f.cleanup().await;
    }

    #[test]
    fn move_into_a_channel_the_target_cannot_join_is_allowed() {
        crate::util::test::rt()
            .block_on(move_into_a_channel_the_target_cannot_join_is_allowed_case())
    }

    /// A timeout channel: the target can see it but not Connect to it. The
    /// moderator may still put them there.
    async fn move_into_a_channel_the_target_cannot_join_is_allowed_case() {
        let f = move_fixture(true).await;
        let benched = ranked_role(&f.harness, &f.server, 2, 0).await;
        give_role(&f.harness, &f.server, &f.target, &benched).await;
        channel_override(
            &f.harness,
            &f.dest,
            &benched,
            0,
            ChannelPermission::Connect as u64,
        )
        .await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        f.cleanup().await;
    }

    #[test]
    fn self_move_into_a_full_channel_is_refused() {
        crate::util::test::rt().block_on(self_move_into_a_full_channel_is_refused_case())
    }

    /// Moving yourself is a join and gets the join's user limit, including
    /// its ManageChannel exemption; a moderator move is not held to it.
    async fn self_move_into_a_full_channel_is_refused_case() {
        let f = move_fixture(true).await;
        let full = limited_voice_channel(&f.harness, &f.server, "Full", Some(1)).await;
        let full_uvc = UserVoiceChannel::from_channel(&full);
        let occupant = "0SYNTHFULLCHANNELUSER00000".to_string();
        create_voice_state(&full_uvc, &occupant, Timestamp::now_utc())
            .await
            .expect("occupant");

        let response = move_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            full.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest);
        assert!(
            matches!(error, revolt_result::ErrorType::CannotJoinCall),
            "a self-move into a full channel must be refused like a join, got {:?}",
            error
        );

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            full.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        let manager = ranked_role(&f.harness, &f.server, 2, 0).await;
        give_role(&f.harness, &f.server, &f.target, &manager).await;
        channel_override(
            &f.harness,
            &full,
            &manager,
            ChannelPermission::ManageChannel as u64,
            0,
        )
        .await;

        let response = move_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            full.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        delete_channel_voice_state(&full_uvc, &[occupant])
            .await
            .expect("cleanup full");
        f.cleanup().await;
    }

    async fn disconnect_member<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        target_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        edit_member(
            harness,
            token,
            server_id,
            target_id,
            serde_json::json!({ "remove": ["VoiceChannel"] }),
        )
        .await
    }

    #[test]
    fn disconnect_needs_move_members_on_the_source_channel() {
        crate::util::test::rt().block_on(disconnect_needs_move_members_on_the_source_channel_case())
    }

    async fn disconnect_needs_move_members_on_the_source_channel_case() {
        let f = move_fixture(true).await;
        channel_override(
            &f.harness,
            &f.source,
            &f.mod_role,
            0,
            ChannelPermission::MoveMembers as u64,
        )
        .await;

        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_missing_permission(response, ChannelPermission::MoveMembers).await;

        f.cleanup().await;
    }

    #[test]
    fn disconnect_with_move_members_on_the_source_channel_proceeds() {
        crate::util::test::rt()
            .block_on(disconnect_with_move_members_on_the_source_channel_proceeds_case())
    }

    async fn disconnect_with_move_members_on_the_source_channel_proceeds_case() {
        let f = move_fixture(false).await;
        channel_override(
            &f.harness,
            &f.source,
            &f.mod_role,
            ChannelPermission::MoveMembers as u64,
            0,
        )
        .await;

        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_reached_livekit(response).await;

        f.cleanup().await;
    }

    #[test]
    fn disconnect_of_a_member_not_in_voice_keeps_the_server_check() {
        crate::util::test::rt()
            .block_on(disconnect_of_a_member_not_in_voice_keeps_the_server_check_case())
    }

    async fn disconnect_of_a_member_not_in_voice_keeps_the_server_check_case() {
        let f = move_fixture(false).await;
        f.cleanup().await;

        // No source channel to scope to, so a channel override grants nothing.
        channel_override(
            &f.harness,
            &f.source,
            &f.mod_role,
            ChannelPermission::MoveMembers as u64,
            0,
        )
        .await;
        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_missing_permission(response, ChannelPermission::MoveMembers).await;

        // Granting it server-wide is what lets the disconnect through.
        let mut role = f.mod_role.clone();
        role.update(
            &f.harness.db,
            &f.server.id,
            PartialRole {
                permissions: Some(OverrideField {
                    a: ChannelPermission::MoveMembers as i64,
                    d: 0,
                }),
                ..Default::default()
            },
            Vec::new(),
        )
        .await
        .expect("server-wide MoveMembers");

        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_eq!(response.status(), Status::Ok);
    }

    async fn assert_not_elevated(response: rocket::local::asynchronous::LocalResponse<'_>) {
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Forbidden, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::NotElevated),
            "a mover who does not outrank the target must get NotElevated \
             before any voice check can answer, got {:?}",
            error
        );
    }

    #[test]
    fn a_mover_who_does_not_outrank_the_target_learns_nothing() {
        crate::util::test::rt()
            .block_on(a_mover_who_does_not_outrank_the_target_learns_nothing_case())
    }

    /// The rank check runs before every voice lookup. Each request below would
    /// otherwise be answered by a voice check that describes the TARGET (what
    /// they can see, which channel they are in, whether they are in voice at
    /// all) to a moderator with no standing to act on them.
    async fn a_mover_who_does_not_outrank_the_target_learns_nothing_case() {
        let f = move_fixture(true).await;
        let senior = ranked_role(&f.harness, &f.server, 0, 0).await;
        give_role(&f.harness, &f.server, &f.target, &senior).await;
        channel_override(
            &f.harness,
            &f.dest,
            &senior,
            0,
            ChannelPermission::ViewChannel as u64,
        )
        .await;

        // A destination the target cannot see: MissingPermission ViewChannel
        // if the destination checks ran first.
        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_not_elevated(response).await;

        // A disconnect out of a source the mover lacks MoveMembers on:
        // MissingPermission MoveMembers only while the target is in there.
        channel_override(
            &f.harness,
            &f.source,
            &f.mod_role,
            0,
            ChannelPermission::MoveMembers as u64,
        )
        .await;
        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_not_elevated(response).await;
        assert!(
            get_voice_state(&f.source_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused disconnect must leave the target connected"
        );

        // A target not in voice at all: NotConnected if the destination
        // checks ran first.
        f.cleanup().await;
        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_not_elevated(response).await;
    }

    #[test]
    fn a_source_with_no_node_refuses_the_move_and_allows_the_disconnect() {
        crate::util::test::rt()
            .block_on(a_source_with_no_node_refuses_the_move_and_allows_the_disconnect_case())
    }

    /// The target's voice state outlived the channel's node mapping. Both
    /// actions used to `unwrap()` the node after the member was updated and
    /// panic into a 500.
    async fn a_source_with_no_node_refuses_the_move_and_allows_the_disconnect_case() {
        let f = move_fixture(true).await;
        delete_channel_node(f.source.id()).await.expect("drop node");

        // A move needs the old node to evict the target from: refused, and
        // refused before anything was written.
        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::NotConnected),
            "a move out of a channel with no node must be NotConnected, got {:?}",
            error
        );
        assert!(
            get_voice_state(&f.source_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused move must leave the target's voice state alone"
        );

        // A disconnect with no room to kick from has nothing left to do.
        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_eq!(response.status(), Status::Ok);

        f.cleanup().await;
    }

    /// The re-read before the first side effect cannot be raced from a route
    /// test deterministically (both reads happen inside one request with no
    /// seam between them), so the decision it feeds is pinned here directly.
    #[test]
    fn a_voice_channel_change_after_the_checks_is_refused() {
        use revolt_result::ErrorType;

        let decide = |checked: Option<&str>, current: Option<&str>| {
            super::assert_voice_channel_unchanged(checked, current).map_err(|e| e.error_type)
        };

        assert!(decide(Some("A"), Some("A")).is_ok(), "unchanged");
        assert!(decide(None, None).is_ok(), "still not in voice");
        assert!(
            matches!(decide(Some("A"), None), Err(ErrorType::NotConnected)),
            "left after the checks"
        );
        assert!(
            matches!(
                decide(Some("A"), Some("B")),
                Err(ErrorType::InvalidOperation)
            ),
            "hopped to a channel nobody checked"
        );
        assert!(
            matches!(decide(None, Some("B")), Err(ErrorType::InvalidOperation)),
            "joined after the checks saw them out of voice"
        );
    }

    #[test]
    fn move_event_url_is_the_nodes_public_url() {
        let mut config = crate::util::test::rt().block_on(revolt_config::config());
        config.hosts.livekit.clear();
        config
            .hosts
            .livekit
            .insert("known".to_string(), "wss://voice.example".to_string());

        assert_eq!(
            super::move_event_url(&config, "known").as_deref(),
            Some("wss://voice.example")
        );
        assert_eq!(super::move_event_url(&config, "unknown"), None);
    }

    // ---- who receives the move token -------------------------------------
    //
    // A move that clears every check dies at `create_room` on the absent node,
    // before anything is published, so the delivery decision is pinned on the
    // pure functions and the refusals on the route.

    #[test]
    fn a_device_qualified_move_token_goes_to_the_bound_session_only() {
        use super::{move_event_delivery, MoveDelivery};

        assert_eq!(
            move_event_delivery(Some("dev"), Some("bound")),
            MoveDelivery::Session {
                session_id: "bound".to_string(),
                device_id: "dev".to_string()
            },
            "qualified + bound: only the bound session gets the token"
        );
        assert_eq!(
            move_event_delivery(Some(""), Some("bound")),
            MoveDelivery::UserNoToken,
            "empty device suffix with a bound session: fails closed"
        );
        assert_eq!(
            move_event_delivery(Some("dev"), None),
            MoveDelivery::UserNoToken,
            "qualified + no identity row (never registered, or revoked): no token"
        );
        assert_eq!(
            move_event_delivery(Some("dev"), Some("")),
            MoveDelivery::UserNoToken,
            "qualified + no bound session: no token"
        );
        assert_eq!(
            move_event_delivery(Some(""), None),
            MoveDelivery::UserNoToken,
            "empty device suffix: fails closed"
        );
        assert_eq!(
            move_event_delivery(None, None),
            MoveDelivery::User,
            "bare identity: bare token to every session"
        );
        assert_eq!(
            move_event_delivery(None, Some("bound")),
            MoveDelivery::User,
            "bare identity ignores any row"
        );
    }

    /// The route mints and publishes from this plan alone, so these pin
    /// which device a move token is minted for and which topic carries it.
    #[test]
    fn a_move_token_plan_pins_the_minted_device_and_the_topic() {
        use super::{move_token_plan, MoveDelivery, MoveTokenPlan, MoveTopic};

        let session = MoveDelivery::Session {
            session_id: "bound".to_string(),
            device_id: "dev".to_string(),
        };
        let plan = move_token_plan(&session);
        assert_eq!(
            plan.mint,
            Some(Some("dev")),
            "session delivery: the token is minted for the device"
        );
        assert_eq!(
            plan.topic,
            MoveTopic::Session("bound"),
            "session delivery: published to the bound session only"
        );
        assert_eq!(
            plan,
            MoveTokenPlan {
                mint: Some(Some("dev")),
                topic: MoveTopic::Session("bound"),
            }
        );

        let plan = move_token_plan(&MoveDelivery::User);
        assert_eq!(
            plan.mint,
            Some(None),
            "user delivery: a bare token, never a device-qualified one"
        );
        assert_eq!(plan.topic, MoveTopic::User, "user delivery: every session");

        let plan = move_token_plan(&MoveDelivery::UserNoToken);
        assert_eq!(plan.mint, None, "no-token delivery: nothing is minted");
        assert_eq!(
            plan.topic,
            MoveTopic::User,
            "no-token delivery: every session"
        );
    }

    #[test]
    fn a_move_mints_a_qualified_identity_only_with_media_e2ee_on() {
        use super::qualified_move_device;

        let user = "01USER0000000000000000000A";
        let qualified = format!("{user}:{}", "ab".repeat(16));
        let device = "ab".repeat(16);

        assert_eq!(
            qualified_move_device(&qualified, user, true),
            Some(device.as_str())
        );
        assert_eq!(qualified_move_device(user, user, true), None, "bare");
        assert_eq!(
            qualified_move_device(&qualified, user, false),
            None,
            "media E2EE off: the move takes the bare path, as join_call only \
             admits bare identities then"
        );
        assert_eq!(
            qualified_move_device(&format!("{user}X:dev"), user, true),
            None,
            "a longer user id sharing the prefix is not this user's device"
        );
        assert_eq!(
            qualified_move_device(&format!("{user}:"), user, true),
            Some(""),
            "an empty suffix stays qualified, so it fails closed"
        );
    }

    fn identity_row(user_id: &str, device_id: &str, last_session_id: &str) -> E2EEIdentity {
        E2EEIdentity {
            id: E2EEIdentity::composite_id(user_id, device_id),
            user_id: user_id.to_string(),
            device_id: device_id.to_string(),
            protocol_version: 1,
            ed25519_key: "ed25519".to_string(),
            curve25519_key: "curve25519".to_string(),
            signature: "signature".to_string(),
            fallback_key: E2EESignedKey {
                key_id: "fallback0".to_string(),
                key: "key".to_string(),
                signature: "signature".to_string(),
            },
            previous_fallback_key: None,
            created_at: Timestamp::now_utc(),
            last_seen_at: Timestamp::now_utc(),
            last_session_id: last_session_id.to_string(),
        }
    }

    #[test]
    fn a_revoked_device_gets_no_move_token() {
        crate::util::test::rt().block_on(a_revoked_device_gets_no_move_token_case())
    }

    /// Revocation deletes the identity row, so the route's lookup must come
    /// back empty for it and the delivery must carry no token.
    async fn a_revoked_device_gets_no_move_token_case() {
        use super::{fetch_device_identity, move_event_delivery, MoveDelivery};

        let harness = TestHarness::new().await;
        let (_a, session, user) = harness.new_user().await;
        let device = "cd".repeat(16);
        harness
            .db
            .insert_e2ee_identity(&identity_row(&user.id, &device, &session.id))
            .await
            .expect("identity");

        let row = fetch_device_identity(&harness.db, &user.id, &device)
            .await
            .expect("lookup");
        assert_eq!(
            move_event_delivery(
                Some(&device),
                row.as_ref().map(|r| r.last_session_id.as_str())
            ),
            MoveDelivery::Session {
                session_id: session.id.clone(),
                device_id: device.clone()
            }
        );

        E2EEIdentity::revoke_device(&harness.db, &user.id, &device)
            .await
            .expect("revoke");

        let row = fetch_device_identity(&harness.db, &user.id, &device)
            .await
            .expect("lookup");
        assert!(row.is_none(), "a revoked device has no identity row");
        assert_eq!(
            move_event_delivery(
                Some(&device),
                row.as_ref().map(|r| r.last_session_id.as_str())
            ),
            MoveDelivery::UserNoToken
        );
    }

    #[test]
    fn a_web_session_cannot_self_move_a_device_bound_participant() {
        crate::util::test::rt()
            .block_on(a_web_session_cannot_self_move_a_device_bound_participant_case())
    }

    /// The target is in the call as `target:device`. Their web session (not
    /// bound to the device) moving them would be handed a token for the
    /// device's identity, so it is refused before anything is written. The
    /// bound session, a moderator, and a bare participant are unaffected.
    async fn a_web_session_cannot_self_move_a_device_bound_participant_case() {
        let f = move_fixture(true).await;
        let device = "ef".repeat(16);
        set_voice_participant_identity(
            f.source.id(),
            &f.target.id,
            &format!("{}:{device}", f.target.id),
        )
        .await
        .expect("identity mapping");

        // `target_token` is the web session; this one is bound to the device.
        let account = f
            .harness
            .db
            .fetch_account(&f.target.id)
            .await
            .expect("account");
        let bound = account
            .create_session(&f.harness.db, String::new())
            .await
            .expect("bound session");

        // No identity row yet: refused like a join from an unregistered device.
        let response = move_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::FailedValidation { .. }),
            "an unregistered device must be refused, got {:?}",
            error
        );

        f.harness
            .db
            .insert_e2ee_identity(&identity_row(&f.target.id, &device, &bound.id))
            .await
            .expect("identity");

        let response = move_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Unauthorized, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::NotAuthenticated),
            "a web session must not self-move a device-bound participant, got {:?}",
            error
        );
        assert!(
            get_voice_state(&f.source_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused move must leave the target connected"
        );
        assert_eq!(
            get_user_moved_from_voice(f.source.id(), &f.target.id)
                .await
                .expect("moved_from read"),
            None,
            "the refused move must write nothing"
        );

        // A moderator's move is not a join by the target: it passes, and the
        // token goes to the bound session (pinned on the pure function).
        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        // The bound session may move itself.
        let response = move_member(
            &f.harness,
            &bound.token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        // A bare participant has no device to impersonate: any session moves.
        delete_voice_participant_identity(f.source.id(), &f.target.id)
            .await
            .expect("drop mapping");
        let response = move_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        f.cleanup().await;
    }

    #[test]
    fn a_bot_edit_needs_no_session() {
        crate::util::test::rt().block_on(a_bot_edit_needs_no_session_case())
    }

    /// Bots authenticate with `x-bot-token` and have no session. Their edits
    /// keep working; a self-move out of a device-qualified identity (which a
    /// bot cannot legitimately hold) fails closed.
    async fn a_bot_edit_needs_no_session_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, owner) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&owner).await;
        let (bot, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("bot");
        Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("member");

        let response = harness
            .client
            .patch(format!("/servers/{}/members/{}", server.id, bot_user.id))
            .header(ContentType::JSON)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .body(serde_json::json!({ "nickname": "Botty" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);

        let source = voice_channel(&harness, &server, "Source").await;
        let dest = voice_channel(&harness, &server, "Dest").await;
        let source_uvc = UserVoiceChannel::from_channel(&source);
        create_voice_state(&source_uvc, &bot_user.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        set_channel_node(source.id(), ABSENT_NODE)
            .await
            .expect("node");
        set_voice_participant_identity(
            source.id(),
            &bot_user.id,
            &format!("{}:{}", bot_user.id, "01".repeat(16)),
        )
        .await
        .expect("identity mapping");

        let response = harness
            .client
            .patch(format!("/servers/{}/members/{}", server.id, bot_user.id))
            .header(ContentType::JSON)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .body(serde_json::json!({ "voice_channel": dest.id() }).to_string())
            .dispatch()
            .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Unauthorized, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::NotAuthenticated),
            "a sessionless self-move of a device identity must fail closed, got {:?}",
            error
        );

        delete_voice_participant_identity(source.id(), &bot_user.id)
            .await
            .expect("drop mapping");
        delete_channel_voice_state(&source_uvc, &[bot_user.id.clone()])
            .await
            .expect("cleanup");
    }

    // ---- voice permission sync on member edit ----------------------------
    //
    // The sync's LiveKit leg cannot be exercised without a live SFU, but it
    // runs AFTER `update_voice_state`, so the redis voice state is a faithful
    // observable for "did the sync run, and against whom". `is_publishing` is
    // recomputed as `voice_state.is_publishing && can_speak`, so a member
    // seeded as publishing flips to false exactly when a sync that saw their
    // real permissions ran against them — and stays true when the sync was
    // skipped, or was aimed at the wrong user, or read a stale permission set.

    /// Node these tests pin their voice channels to.
    ///
    /// Deliberately NOT a node in `Revolt.toml`: `update_permissions` resolves
    /// the node name before it touches the network, so an unknown one turns the
    /// unreachable-SFU call into an immediate `UnknownNode` instead of a ~25s
    /// DNS/connect stall — which sat right on nextest's 50s kill threshold.
    /// Everything these tests assert on happens before that point.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    /// PATCH the target member with an arbitrary body, acting as `mod_token`.
    async fn edit_member<'a>(
        harness: &'a TestHarness,
        mod_token: &str,
        server_id: &str,
        target_id: &str,
        body: serde_json::Value,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .patch(format!("/servers/{server_id}/members/{target_id}"))
            .header(ContentType::JSON)
            .header(Header::new("x-session-token", mod_token.to_string()))
            .body(body.to_string())
            .dispatch()
            .await
    }

    /// Connect `user_id` to `channel` as a publishing participant on a node.
    async fn connect_publishing(channel: &Channel, user_id: &str) -> UserVoiceChannel {
        let uvc = UserVoiceChannel::from_channel(channel);

        create_voice_state(&uvc, user_id, Timestamp::now_utc())
            .await
            .expect("voice state");
        update_voice_state(
            &uvc,
            user_id,
            &v0::PartialUserVoiceState {
                is_publishing: Some(true),
                ..Default::default()
            },
        )
        .await
        .expect("publishing flag");
        set_channel_node(channel.id(), ABSENT_NODE)
            .await
            .expect("node");

        uvc
    }

    async fn is_publishing(uvc: &UserVoiceChannel, user_id: &str) -> bool {
        get_voice_state(uvc, user_id)
            .await
            .expect("voice state read")
            .expect("voice state present")
            .is_publishing
    }

    /// Server owner + a plain member connected and publishing in a voice channel.
    async fn muted_member_harness() -> (TestHarness, String, Server, User, UserVoiceChannel) {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // moderator = owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect_publishing(&channel, &user_b.id).await;

        (harness, session_a.token, server, user_b, uvc)
    }

    #[test]
    fn server_mute_syncs_the_target_not_the_moderator() {
        crate::util::test::rt().block_on(server_mute_syncs_the_target_not_the_moderator_case())
    }

    async fn server_mute_syncs_the_target_not_the_moderator_case() {
        let (harness, token, server, target, uvc) = muted_member_harness().await;

        edit_member(
            &harness,
            &token,
            &server.id,
            &target.id,
            serde_json::json!({ "can_publish": false }),
        )
        .await;

        assert!(
            !is_publishing(&uvc, &target.id).await,
            "server-mute must sync the TARGET's participant — passing the acting \
             moderator early-returned on their missing voice state, so the mute \
             never reached the target's SFU participant"
        );

        delete_channel_voice_state(&uvc, &[target.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn granting_a_voice_denying_role_syncs_the_target() {
        crate::util::test::rt().block_on(granting_a_voice_denying_role_syncs_the_target_case())
    }

    async fn granting_a_voice_denying_role_syncs_the_target_case() {
        let (harness, token, server, target, uvc) = muted_member_harness().await;

        // A role that takes Speak away from whoever holds it.
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: 0,
                    d: ChannelPermission::Speak as i64,
                }),
            )
            .await;

        edit_member(
            &harness,
            &token,
            &server.id,
            &target.id,
            serde_json::json!({ "roles": [role.id] }),
        )
        .await;

        // Two regressions in one: role edits did not trigger a sync at all, and
        // the rank check `remove`d the added role from the local server copy —
        // so even once triggered the sync computed the pre-edit permissions.
        assert!(
            !is_publishing(&uvc, &target.id).await,
            "a role change must re-sync voice permissions, and the sync must see \
             the role that was just granted"
        );

        delete_channel_voice_state(&uvc, &[target.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn stripping_a_voice_granting_role_syncs_the_target() {
        crate::util::test::rt().block_on(stripping_a_voice_granting_role_syncs_the_target_case())
    }

    async fn stripping_a_voice_granting_role_syncs_the_target_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (mut server, _channels) = harness.new_server(&user_a).await;

        // Speak comes from a role here, not from the server default, so taking
        // the role away is observable.
        server
            .update(
                &harness.db,
                PartialServer {
                    default_permissions: Some(
                        (ChannelPermission::ViewChannel
                            + ChannelPermission::ReadMessageHistory
                            + ChannelPermission::Connect
                            + ChannelPermission::Listen) as i64,
                    ),
                    ..Default::default()
                },
                Vec::new(),
            )
            .await
            .expect("default permissions");

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::Speak as i64,
                    d: 0,
                }),
            )
            .await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Voice").await;
        let uvc = connect_publishing(&channel, &user_b.id).await;

        edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "roles": [role.id] }),
        )
        .await;
        assert!(
            is_publishing(&uvc, &user_b.id).await,
            "the granted role allows Speak, so the sync must leave them publishing"
        );

        edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "roles": [] }),
        )
        .await;
        assert!(
            !is_publishing(&uvc, &user_b.id).await,
            "stripping the role that granted Speak must re-sync the target — it \
             used to leave the SFU honouring the revoked grant"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn timing_a_member_out_syncs_their_voice_permissions() {
        crate::util::test::rt().block_on(timing_a_member_out_syncs_their_voice_permissions_case())
    }

    async fn timing_a_member_out_syncs_their_voice_permissions_case() {
        let (harness, token, server, target, uvc) = muted_member_harness().await;

        let until = Timestamp::now_utc()
            .checked_add(Duration::hours(1))
            .expect("timeout timestamp");

        edit_member(
            &harness,
            &token,
            &server.id,
            &target.id,
            serde_json::json!({ "timeout": until }),
        )
        .await;

        // A timeout restricts down to ALLOW_IN_TIMEOUT, which has no Speak.
        assert!(
            !is_publishing(&uvc, &target.id).await,
            "timing a member out must re-sync their voice permissions — they \
             used to keep publishing to the SFU for the whole timeout"
        );

        delete_channel_voice_state(&uvc, &[target.id.clone()])
            .await
            .expect("cleanup");
    }

    // ---- clearing a voice override is a moderation action ----------------
    //
    // `can_publish` / `can_receive` are server-mute and server-deafen. Setting
    // them false is permission-checked, but RESETTING them to true travels as
    // `remove: ["CanPublish"]`, which used to pass through the route with no
    // permission check at all — and self-edits skip the rank check, so a muted
    // member could lift their own mute with a single PATCH. These pin the
    // check onto the clear path, in both directions.

    #[test]
    fn muted_member_cannot_clear_their_own_mute() {
        crate::util::test::rt().block_on(muted_member_cannot_clear_their_own_mute_case())
    }

    async fn muted_member_cannot_clear_their_own_mute_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        // Owner server-mutes and server-deafens the member.
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": false, "can_receive": false }),
        )
        .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "the owner holds both permissions"
        );

        // The member may not lift it. Refused as InvalidOperation rather than
        // MissingPermission because the no-self-moderation rule is checked
        // first and holds regardless of permissions — see
        // `a_moderator_cannot_lift_their_own_mute` for the case where the
        // actor DOES hold them.
        for field in ["CanPublish", "CanReceive"] {
            let response = edit_member(
                &harness,
                &session_b.token,
                &server.id,
                &user_b.id,
                serde_json::json!({ "remove": [field] }),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::BadRequest,
                "clearing {field} lifts a moderation action against yourself \
                 and must be refused"
            );
        }

        // The override is still in place on the stored member.
        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(
            !member.can_publish,
            "the mute must survive the refused clear"
        );
        assert!(
            !member.can_receive,
            "the deafen must survive the refused clear"
        );
    }

    #[test]
    fn clearing_another_members_mute_needs_the_permission() {
        crate::util::test::rt().block_on(clearing_another_members_mute_needs_the_permission_case())
    }

    /// The permission half of the same gate, against a THIRD party so the
    /// no-self-moderation rule cannot mask it: a member holding neither
    /// permission gets MissingPermission on the `remove` shape, which used to
    /// pass through the route entirely unchecked.
    async fn clearing_another_members_mute_needs_the_permission_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // muted target
        let (_c, session_c, user_c) = harness.new_user().await; // bystander
        let (server, _channels) = harness.new_server(&user_a).await;
        for user in [&user_b, &user_c] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": false, "can_receive": false }),
        )
        .await;

        for field in ["CanPublish", "CanReceive"] {
            let response = edit_member(
                &harness,
                &session_c.token,
                &server.id,
                &user_b.id,
                serde_json::json!({ "remove": [field] }),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::Forbidden,
                "clearing {field} on someone else needs the permission that \
                 applied it"
            );
        }

        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(
            !member.can_publish,
            "the mute must survive the refused clear"
        );
        assert!(
            !member.can_receive,
            "the deafen must survive the refused clear"
        );
    }

    #[test]
    fn a_moderator_cannot_lift_their_own_mute() {
        crate::util::test::rt().block_on(a_moderator_cannot_lift_their_own_mute_case())
    }

    /// The permission check alone does not close the self-unmute path: the
    /// rank check is skipped for a self-edit, so a moderator who HOLDS
    /// MuteMembers and has been muted would otherwise lift it themselves.
    /// This is the case the "holds neither permission" test cannot reach.
    async fn a_moderator_cannot_lift_their_own_mute_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // moderator
        let (server, _channels) = harness.new_server(&user_a).await;

        // A role that grants the moderator both voice-moderation permissions.
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::MuteMembers as i64
                        + ChannelPermission::DeafenMembers as i64,
                    d: 0,
                }),
            )
            .await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "roles": [role.id] }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok, "owner may assign the role");

        // Owner mutes and deafens the moderator.
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": false, "can_receive": false }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        // Every shape the moderator could reach for, holding the permission.
        for body in [
            serde_json::json!({ "can_publish": true }),
            serde_json::json!({ "remove": ["CanPublish"] }),
            serde_json::json!({ "can_receive": true }),
            serde_json::json!({ "remove": ["CanReceive"] }),
        ] {
            let response = edit_member(
                &harness,
                &session_b.token,
                &server.id,
                &user_b.id,
                body.clone(),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::BadRequest,
                "{body} is a self-edit of a moderation action and must be \
                 refused even though the actor holds the permission"
            );
        }

        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(!member.can_publish, "the mute must still stand");
        assert!(!member.can_receive, "the deafen must still stand");
    }

    #[test]
    fn a_moderator_cannot_act_on_an_owner_with_no_roles() {
        crate::util::test::rt()
            .block_on(a_moderator_cannot_act_on_an_owner_with_no_roles_case())
    }

    /// An owner holding no roles used to rank `i64::MAX`, below every role,
    /// so a moderator passed the rank check against them and could mute,
    /// deafen or rename the owner of the server.
    async fn a_moderator_cannot_act_on_an_owner_with_no_roles_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner, no roles
        let (_b, session_b, user_b) = harness.new_user().await; // moderator
        let (server, _channels) = harness.new_server(&user_a).await;

        // The harness inserts the server without the owner's membership,
        // which a real server always has.
        if harness.db.fetch_member(&server.id, &user_a.id).await.is_err() {
            Member::create(&harness.db, &server, &user_a, None)
                .await
                .expect("owner member");
        }

        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::MuteMembers as i64
                        + ChannelPermission::DeafenMembers as i64
                        + ChannelPermission::ManageNicknames as i64,
                    d: 0,
                }),
            )
            .await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "roles": [role.id] }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok, "owner may assign the role");

        let owner = harness
            .db
            .fetch_member(&server.id, &user_a.id)
            .await
            .expect("owner member");
        assert!(owner.roles.is_empty(), "the owner must hold no roles here");

        for body in [
            serde_json::json!({ "can_publish": false }),
            serde_json::json!({ "can_receive": false }),
            serde_json::json!({ "nickname": "renamed" }),
        ] {
            let response = edit_member(
                &harness,
                &session_b.token,
                &server.id,
                &user_a.id,
                body.clone(),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::Forbidden,
                "{body} against the owner must be refused"
            );
            // MissingPermission is a 403 too, so pin the reason.
            let error: revolt_result::Error =
                response.into_json().await.expect("error body");
            assert!(
                matches!(error.error_type, revolt_result::ErrorType::NotElevated),
                "{body} must fail on rank, not permission: {:?}",
                error.error_type
            );
        }

        let owner = harness
            .db
            .fetch_member(&server.id, &user_a.id)
            .await
            .expect("owner member");
        assert!(owner.can_publish, "the owner must not be muted");
        assert!(owner.can_receive, "the owner must not be deafened");
        assert!(owner.nickname.is_none(), "the owner must not be renamed");

        // The moderator still outranks an ordinary member with no roles, and
        // each of the three edits above is one the role really grants.
        let (_c, _session_c, user_c) = harness.new_user().await;
        Member::create(&harness.db, &server, &user_c, None)
            .await
            .expect("member");
        // One request carrying all three, so the moderator stays under the
        // edit rate limit; it succeeds only if the role grants every one.
        let response = edit_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            serde_json::json!({
                "can_publish": false,
                "can_receive": false,
                "nickname": "renamed"
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "the same edits against a plain member must succeed"
        );
    }

    #[test]
    fn setting_and_clearing_one_override_at_once_is_refused() {
        crate::util::test::rt()
            .block_on(setting_and_clearing_one_override_at_once_is_refused_case())
    }

    /// Set-and-clear in one edit resolves differently per driver (Mongo
    /// rejects the conflicting $set/$unset; the reference driver applies the
    /// remove first) and emits an event contradicting the response body.
    async fn setting_and_clearing_one_override_at_once_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        for body in [
            serde_json::json!({ "can_publish": false, "remove": ["CanPublish"] }),
            serde_json::json!({ "can_receive": false, "remove": ["CanReceive"] }),
        ] {
            let response = edit_member(
                &harness,
                &session_a.token,
                &server.id,
                &user_b.id,
                body.clone(),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::BadRequest,
                "{body} sets and clears the same field and must be refused"
            );
        }

        // Nothing was applied on the way to the refusal.
        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(member.can_publish);
        assert!(member.can_receive);
    }

    #[test]
    fn moderator_can_clear_the_mute_they_applied() {
        crate::util::test::rt().block_on(moderator_can_clear_the_mute_they_applied_case())
    }

    async fn moderator_can_clear_the_mute_they_applied_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": false, "can_receive": false }),
        )
        .await;

        // Both shapes a client may use to lift it: the explicit `true`, and
        // the `remove` clear.
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": true }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "remove": ["CanReceive"] }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);

        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(member.can_publish, "the explicit true must lift the mute");
        assert!(member.can_receive, "the clear must lift the deafen");
    }

    #[test]
    fn lifting_a_mute_is_announced_to_the_server() {
        crate::util::test::rt().block_on(lifting_a_mute_is_announced_to_the_server_case())
    }

    /// Clients render the mute badge from `ServerMemberUpdate`, so the event
    /// must carry the value in BOTH directions. `Member::can_publish` is
    /// `skip_serializing_if = "is_true"`, which would drop the un-mute from
    /// the wire and leave every other client showing the member as muted
    /// forever; this pins that the partial does not inherit that behaviour.
    async fn lifting_a_mute_is_announced_to_the_server_case() {
        let mut harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": false }),
        )
        .await;

        let target = user_b.id.clone();
        harness
            .wait_for_event(&server.id, |event| match event {
                EventV1::ServerMemberUpdate { id, data, .. } => {
                    id.user == target && data.can_publish == Some(false)
                }
                _ => false,
            })
            .await;

        edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": true }),
        )
        .await;

        let target = user_b.id.clone();
        harness
            .wait_for_event(&server.id, |event| match event {
                EventV1::ServerMemberUpdate { id, data, .. } => {
                    id.user == target && data.can_publish == Some(true)
                }
                _ => false,
            })
            .await;
    }

    // ---- nickname slur filter --------------------------------------------

    #[test]
    fn reject_slur_in_nickname() {
        crate::util::test::rt().block_on(reject_slur_in_nickname_case())
    }

    async fn reject_slur_in_nickname_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        Member::create(&harness.db, &server, &user, None)
            .await
            .expect("member");

        // Punctuation between the letters is stripped before matching.
        let response = edit_member(
            &harness,
            &session.token,
            &server.id,
            &user.id,
            serde_json::json!({ "nickname": "F.A.G." }),
        )
        .await;

        assert_eq!(response.status(), Status::BadRequest);
    }

    #[test]
    fn allow_ordinary_nickname() {
        crate::util::test::rt().block_on(allow_ordinary_nickname_case())
    }

    async fn allow_ordinary_nickname_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user).await;
        Member::create(&harness.db, &server, &user, None)
            .await
            .expect("member");

        let response = edit_member(
            &harness,
            &session.token,
            &server.id,
            &user.id,
            serde_json::json!({ "nickname": "Spicy Chef" }),
        )
        .await;

        assert_eq!(response.status(), Status::Ok);
    }

    // ---- which edits require a sync (pure) -------------------------------

    fn member_edit(body: serde_json::Value) -> v0::DataMemberEdit {
        serde_json::from_value(body).expect("valid DataMemberEdit")
    }

    #[test]
    fn voice_affecting_edits_trigger_a_sync() {
        for body in [
            serde_json::json!({ "can_publish": false }),
            serde_json::json!({ "can_receive": false }),
            serde_json::json!({ "roles": [] }),
            serde_json::json!({ "timeout": Timestamp::now_utc() }),
            serde_json::json!({ "remove": ["CanPublish"] }),
            serde_json::json!({ "remove": ["CanReceive"] }),
            serde_json::json!({ "remove": ["Roles"] }),
            serde_json::json!({ "remove": ["Timeout"] }),
            serde_json::json!({ "nickname": "nick", "remove": ["Timeout"] }),
        ] {
            assert!(
                super::edit_affects_voice_permissions(&member_edit(body.clone())),
                "{body} changes effective voice permissions and must trigger a sync"
            );
        }
    }

    #[test]
    fn non_voice_edits_do_not_trigger_a_sync() {
        for body in [
            serde_json::json!({}),
            serde_json::json!({ "nickname": "nick" }),
            serde_json::json!({ "pronouns": "they/them" }),
            serde_json::json!({ "remove": ["Nickname", "Pronouns", "Avatar"] }),
        ] {
            assert!(
                !super::edit_affects_voice_permissions(&member_edit(body.clone())),
                "{body} cannot change voice permissions and must not sync"
            );
        }
    }
}
