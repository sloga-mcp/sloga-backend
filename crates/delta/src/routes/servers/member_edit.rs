use std::collections::HashSet;

use revolt_database::{
    util::{
        name_filter::contains_blocked_slur, permissions::DatabasePermissionQuery,
        reference::Reference,
    },
    voice::{
        assert_voice_move_admissible, get_channel_node, get_user_voice_channel_in_server,
        holds_voice_state_in, move_user_to_voice_channel_expecting, recorded_voice_connections,
        sync_user_voice_permissions, tear_down_removed_connections, EvictionFailure,
        UserVoiceChannel, VoiceClient, VoiceMoveOutcome,
    },
    Channel, Database, File, PartialMember, User,
};
use revolt_models::v0::{self, FieldsMember};

use revolt_permissions::{
    calculate_channel_permissions, calculate_server_permissions, ChannelPermission,
};
use revolt_result::{create_error, Result};
use rocket::{form::validate::Contains, serde::json::Json, State};
use validator::Validate;

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

/// The acting user's own standing ON THE DESTINATION of a voice move.
///
/// This is not the `MoveMembers` check the route already runs. That one is
/// computed from `DatabasePermissionQuery::new(db, &user).server(&server)`,
/// which is server-scoped and never reads a channel override — so a role that
/// holds `MoveMembers` at the server level passes it even on a private voice
/// channel whose overrides deny that role outright. Without this gate the
/// privileged door is wider than the front door: a moderator who cannot see
/// or enter a channel could still pull anybody into it.
///
/// This answers for the DESTINATION only. The other end of the same action —
/// the call the target is pulled out of — is `assert_mover_may_move_out_of`,
/// and it is not optional: gating one end leaves the other wide open.
///
/// Route policy, deliberately NOT folded into `assert_voice_move_admissible`:
/// the primitive behind it runs for the AFK sweep as well, and a sweep has no
/// acting user to evaluate at all.
///
/// `ViewChannel` is required alongside `MoveMembers`. As the permission
/// calculus stands today it is implied — the server-channel arm revokes every
/// bit once `ViewChannel` is missing — so it adds no refusal of its own. It
/// states the rule this gate is actually about (you cannot reach into a
/// channel you cannot see) and keeps the gate correct if that implication
/// ever stops holding.
async fn assert_mover_may_move_into(
    db: &Database,
    user: &User,
    destination: &Channel,
) -> Result<()> {
    let mut query = DatabasePermissionQuery::new(db, user).channel(destination);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;

    Ok(())
}

/// The acting user's own standing on the SOURCE of a voice move, i.e. the
/// call the target is being pulled OUT of.
///
/// Same reasoning as `assert_mover_may_move_into`, applied to the other end,
/// because the reasoning is symmetric: the server-scoped `MoveMembers` check
/// reads no channel override, so a role denied on a private voice channel
/// passes it there too. Gating only the destination left the half of the
/// action that reaches into somebody else's call completely unchecked — a
/// moderator locked out of a private channel could pull its occupants into a
/// channel they do control, and tell a `NotConnected` refusal apart from a
/// successful move to learn who was sitting in it.
///
/// Applies to the disconnect shape (`remove: ["VoiceChannel"]`) as well as
/// the move: kicking somebody out of a call is the same reach into the same
/// channel, minus a destination. That is why the call site sits in the block
/// both shapes pass through rather than inside the move branch.
///
/// `ViewChannel` and `MoveMembers` both, deliberately, and neither costs a
/// legitimate flow. A moderator holding `MoveMembers` at the server level
/// keeps it in every channel that does not explicitly deny it, so the only
/// request this refuses is one an override was written to refuse.
/// `ViewChannel` is implied by the calculus today — the server-channel arm
/// revokes every bit once it is missing — so it adds no refusal of its own;
/// it states the rule (you cannot reach into a channel you cannot see) and
/// keeps the gate correct if that implication ever stops holding.
///
/// Spelled out rather than sharing a body with the destination gate: the
/// contract tests in `revolt-database` read each gate's body and each gate's
/// call site on their own, and the two ends are free to diverge later without
/// one of them silently inheriting the other's rule.
async fn assert_mover_may_move_out_of(db: &Database, user: &User, source: &Channel) -> Result<()> {
    let mut query = DatabasePermissionQuery::new(db, user).channel(source);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;

    Ok(())
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

    // A move combined with an edit that changes the permissions the move is
    // decided UNDER is decided twice, against two different member documents,
    // and both outcomes are wrong:
    //
    // - `{roles: [roleGrantingConnect], voice_channel: D}` — the pre-flight
    //   below reads the member as they stand now, sees no Connect on D and
    //   refuses, so grant-and-move is impossible even though it is exactly
    //   what a moderator means by it.
    // - `{timeout: <future>, voice_channel: afkChannel}` — the pre-flight
    //   passes, the timeout is written and announced, and the move then
    //   recomputes under ALLOW_IN_TIMEOUT, loses Connect and refuses. The
    //   member ends up timed out and NOT moved, which is a half-applied edit
    //   the ordering guarantee below explicitly promises cannot happen.
    //
    // The move deliberately re-reads the member document (see
    // `VoiceMoveAdmission`) so the minted token reflects current permissions;
    // it is the COMBINATION that is incoherent, not either half. Refuse it,
    // the same way the two field collisions above are refused, and the two
    // readings can never disagree. Clients send the two edits in sequence and
    // see each outcome separately.
    //
    // `edit_affects_voice_permissions` is precisely the set that matters here
    // — it exists to answer "does this edit move the member's effective voice
    // permissions" — so the two stay in step by construction.
    if data.voice_channel.is_some() && edit_affects_voice_permissions(&data) {
        return Err(create_error!(InvalidOperation));
    }

    // Resolve our ranking
    let our_ranking = query.get_member_rank().unwrap_or(i64::MIN);

    // Check that we have permissions to act against this member.
    //
    // Hoisted above the voice block below so it is answered before anything
    // inspects a channel. It used to run ~40 lines later, which made the
    // pre-flight's claim that an unauthorized request learns nothing about
    // the destination false: `CannotJoinCall`, `MissingPermission` and
    // `NotConnected` were all reachable by somebody who was going to be told
    // `NotElevated` anyway. For every non-voice edit this is the same
    // position it always held — nothing but the voice block sits between the
    // two — so no other refusal order changes.
    if member.id.user != user.id
        && member.get_ranking(query.server_ref().as_ref().unwrap()) <= our_ranking
    {
        return Err(create_error!(NotElevated));
    }

    // The channel the target is in, read ONCE, and the one the source-side
    // gate below decides about. Every later use in the move path is this
    // value, never a fresh read (AFK Stage 6 F-A3): a fresh read could name a
    // channel the target switched to after the gate ran, one the mover was
    // never checked against. `None` outside the voice shapes, and when the
    // target is in no call in this server.
    let voice_shape =
        data.voice_channel.is_some() || data.remove.contains(&FieldsMember::VoiceChannel);
    let source_id = if voice_shape {
        if !voice_client.is_enabled() {
            return Err(create_error!(LiveKitUnavailable));
        };

        if member.id.user != user.id {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
        }

        // The MOVER's side of the SOURCE — the call the target is being taken
        // out of — evaluated with that channel's own overrides applied. See
        // `assert_mover_may_move_out_of`; the server-scoped `MoveMembers`
        // check just above reads no channel override, so on its own it lets a
        // moderator who is denied on a private voice channel empty it.
        //
        // Sits in this block, not in the move branch below, because the
        // disconnect shape reaches into the same channel the same way and is
        // decided here too — its own eviction runs after the member document
        // has already been written.
        //
        // No source means the target is in no call in this server; there is
        // nothing to be gated on, and the move branch below still answers
        // `NotConnected` in its own place. An unresolvable source channel
        // propagates rather than being waved through: a gate whose subject
        // cannot be read refuses.
        let source_id = get_user_voice_channel_in_server(&target_user.id, &server.id).await?;
        if let Some(source_id) = &source_id {
            let source = Reference::from_unchecked(source_id).as_channel(db).await?;

            // Self-move exemption, same as the destination gate: leaving a
            // call you are in is not exercising `MoveMembers` over anybody.
            if member.id.user != user.id {
                assert_mover_may_move_out_of(db, &user, &source).await?;
            }
        }

        source_id
    } else {
        None
    };

    let new_voice_channel = if let Some(new_channel) = &data.voice_channel {
        // ensure the channel we are moving them to is in the server

        let channel = Reference::from_unchecked(new_channel)
            .as_channel(db)
            .await
            .map_err(|_| create_error!(UnknownChannel))?;

        if channel.server().is_none_or(|v| v != member.id.server) {
            Err(create_error!(UnknownChannel))?
        }

        // The MOVER's side of the move, evaluated with the destination's own
        // overrides applied — see `assert_mover_may_move_into` for why the
        // server-scoped `MoveMembers` check above does not cover it.
        //
        // Skipped for a self-move, consistently with that check: moving
        // yourself is not exercising `MoveMembers` over anybody, and the
        // target-side gates below already answer for you.
        //
        // First of the pre-flight gates on purpose, and now genuinely first:
        // the ranking check and the source-side gate are both answered above,
        // so an unauthorized mover is refused before the destination is
        // inspected at all and a refusal never reports whether the channel is
        // full or who is in it.
        if member.id.user != user.id {
            assert_mover_may_move_into(db, &user, &channel).await?;
        }

        // Every refusal the move itself can raise — the destination really is
        // a voice channel, the TARGET (not the moderator) holds ViewChannel
        // and Connect on it, it is not at `max_users`, and the call-admission
        // caps (D12 video cap + T-20 MLS SFU coupling) admit them. All of it
        // is side-effect free and all of it runs BEFORE any member mutation
        // below, so a refusal leaves the member untouched — the property the
        // caps check was originally placed here for, and the property the
        // mover gates above share.
        //
        // The property survives `move_user_to_voice_channel_expecting` re-deciding all
        // of it AFTER the write only because a PATCH may not combine
        // `voice_channel` with the fields that change these permissions (see
        // the refusal above). Without that, the second reading could refuse
        // an edit the first admitted, leaving it applied and the move not
        // made.
        //
        // `move_user_to_voice_channel_expecting` runs the identical set again when it
        // executes; this is the pre-flight that keeps the ordering guarantee,
        // not a substitute for it.
        assert_voice_move_admissible(db, &target_user, &channel).await?;

        // Route-only precondition, deliberately not part of the primitive:
        // asking to move somebody who is not in a call is a malformed request
        // here, whereas for a sweep it is just an ordinary empty outcome.
        // (It sits after the gates above rather than between them, so a move
        // of a disconnected member into a full destination reports the cap
        // rather than NotConnected. Both refuse, both leave the member
        // untouched.)
        //
        // Answered from the source the gate above decided about, NOT from a
        // fresh read (AFK Stage 6 F-A3). A fresh read here could find the
        // target in a call they joined after the gate saw them in none, and
        // the move would then pull them out of a channel the mover was never
        // checked against. So a move always carries a gated source, and the
        // move itself answers `NotConnected`, doing nothing, if the target
        // has left it by the time it runs.
        let Some(source_id) = source_id.clone() else {
            return Err(create_error!(NotConnected));
        };

        Some((channel, source_id))
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

    if let Some((new_voice_channel, source_id)) = new_voice_channel {
        // The move itself is server-authoritative and lives in the database
        // layer, because the AFK sweep needs the same behavior with no
        // acting user and no Rocket request to hang it off. Everything that
        // is route policy — LiveKit being enabled, `MoveMembers`, ranking —
        // has already been decided above; everything that is about the move
        // being possible and safe is decided in there.
        //
        // EXPECTING the source the mover was gated on (AFK Stage 6 F-A3; the
        // expectation is a required argument since the S-3 cleanup).
        // Re-deriving the source from the pointer would pull a target who
        // switched channels after the gate out of a channel the mover was
        // never authorized over. With the expectation that switch answers
        // `NotConnected` before anything is listed, written or minted.
        //
        // `AlreadyPresent` means there was nothing to do: the target is where
        // they were asked to be, so a 200 is the truth. `NotConnected` means
        // NO move happened - they left, or switched away from the gated
        // source, after the precondition above - and it is answered as the
        // `NotConnected` error the precondition itself gives (AFK Stage 6
        // FU-C), never as a success. It used to be dropped here, which
        // answered 200 for a move that did not happen. The member document
        // above is already written by this point: any nickname, pronouns or
        // avatar sent in the same PATCH stays applied, exactly as it does for
        // every other error the move can raise from here (`UnknownNode`, a
        // caps refusal). The fields that change the permissions a move is
        // decided under cannot be in this PATCH at all (refused above).
        //
        // Matched exhaustively, so a new outcome has to be classified here.
        // The old inline code could not tell these two apart at all: it
        // silently no-op'd on the first and evicted the member from their own
        // call on the second.
        match move_user_to_voice_channel_expecting(
            db,
            voice_client,
            &target_user,
            &new_voice_channel,
            &source_id,
        )
        .await?
        {
            VoiceMoveOutcome::Moved { .. } | VoiceMoveOutcome::AlreadyPresent => {}
            VoiceMoveOutcome::NotConnected => return Err(create_error!(NotConnected)),
        }
    } else if affects_voice_permissions && !remove.contains(&FieldsMember::VoiceChannel) {
        // Skipped when the member is being disconnected outright just below —
        // syncing a participant we are about to evict is pointless, and a
        // failing sync would abort the request before the eviction ran.
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            // No node behind the channel: the call ended between the pointer
            // read and this one (AFK S-3 L-a). There is no participant left
            // to sync and the edit itself is already written, so this is a
            // no-op. It used to `unwrap` here and panic the request.
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
        // EXACTLY the channel the source-side gate decided about, never a
        // fresh read (AFK Stage 6 FU-B, the F-A3 race on the disconnect
        // shape). A fresh read here could name a channel the target switched
        // to after the gate ran, and the mover would kick them out of a call
        // they were never checked against. Addressed to the gated source, a
        // target who has since left it is no longer in the room this removes
        // from, so their new call is untouched.
        //
        // No source at the gate: the target was in no call in this server,
        // and clearing `VoiceChannel` is a no-op, as it always has been (the
        // client's call-moderation policy relies on that).
        //
        // With a source, the removal follows the same rule as
        // `remove_user_from_voice_channel` in the database crate (AFK S-3
        // D-2, amended by WA-R / RA2-1): every connection of the target the
        // SFU lists is evicted, then EXACTLY the connection records this
        // removal knows about are deleted, through the set mode of the
        // teardown script. The reads, the release and the eviction are
        // spelled out here rather than calling that function because the
        // remote-control release carries this route's own reason,
        // `revoked_by_moderator`; the presence check and the teardown are
        // that function's own (`holds_voice_state_in`,
        // `tear_down_removed_connections`, AFK S-3 WB-6 / WB-8).
        //
        // ORDERING RULE: the recorded connections are read BEFORE the SFU
        // listing, never after. Read after, a sibling that records between
        // the listing and the read looks stale (recorded but not listed) and
        // is deleted while live (S-3 WA-1). Read before, such a sibling is in
        // neither set, and `delete_voice_connections`' survivor scan keeps
        // its state. This path decides from a listing, so it NEVER runs the
        // whole-user `delete_voice_state`: that would erase the late
        // sibling's state.
        if let Some(channel) = &source_id {
            let uvc = UserVoiceChannel {
                id: channel.clone(),
                server_id: Some(server.id.clone()),
            };

            // 1. The recorded sids, first. A failed read returns the error
            //    before anything is evicted; it is never taken for an empty
            //    set.
            let recorded: Vec<String> = recorded_voice_connections(&uvc, &target_user.id)
                .await?
                .into_iter()
                .map(|(sid, _)| sid)
                .collect();

            // Whether Redis ties the target to this channel in any other way,
            // read before the listing as well, through the database crate's
            // own check (AFK S-3 WB-6), so this skip and
            // `remove_user_from_voice_channel`'s cannot drift apart:
            // `vc_members:{channel}`, `vc:{user}`, or the per-server pointer
            // naming THIS channel. The pointer is only compared with the gated
            // source there, never used to pick a channel, so FU-B still holds:
            // nothing here can reach a call the gate did not decide about. It
            // used to read the two sets only, and so skipped a target whose
            // only trace here was the pointer, leaving it standing.
            let holds_state =
                !recorded.is_empty() || holds_voice_state_in(&uvc, &target_user.id).await?;

            // 2. The node behind the gated source. None: the call has ended
            //    and there is nothing to evict, but a ghost of it (state or a
            //    record) is still torn down below from the recorded sids, as
            //    `remove_user_from_voice_channel` does. It used to be a no-op
            //    here, which left such a ghost on every roster.
            let node = get_channel_node(channel).await?;

            // Remote-control release hook (plan §1: the moderator disconnect
            // evicts the participant INSIDE delta and would race a
            // webhook-only hook). Before the eviction, and actively revoking
            // (`false`): the eviction below can fail, and then nothing is
            // torn down, so a `can_publish_data` capability must not be
            // assumed gone with it.
            revolt_database::voice::remote_control::release_remote_control_for_user(
                db,
                voice_client,
                &uvc,
                &target_user.id,
                "revoked_by_moderator",
                // Still connected at this point; the disconnect is below.
                false,
            )
            .await;

            // Disconnect the TARGET being removed, not the acting moderator
            // (matches the move branch above; the earlier `user.id` here
            // kicked the moderator out of their own call — 6.6 review
            // finding 8).
            //
            // Whether the acting user may reach into this channel at all was
            // decided in the pre-flight, before the member document was
            // written — not here, where a refusal would be too late.
            //
            // ONE listing of the gated source, every connection of the
            // target in it evicted (primaries and screen legs). `Ok(None)`:
            // the SFU has no such room. `Ok(Some(sids))`: the primaries it
            // listed and evicted, empty when it listed nothing of the target;
            // a target who left between the gate and here is that empty
            // answer, not the 500 the since-deleted `remove_user` gave (F-13). `Err`: a
            // listed connection may still be live, so the error is returned
            // with NOTHING torn down, and the survivor stays visible and
            // syncable. Whether the room was listed (`EvictionFailure`, AFK
            // S-3 WBR-3) does not change that here: this route has always
            // answered either failure with the error (it acts on one gated
            // source, not a server walk), so both map back to the plain
            // error.
            let evicted = match &node {
                Some(node) => voice_client
                    .remove_user_if_present_sids(node, &target_user.id, channel)
                    .await
                    .map_err(EvictionFailure::into_error)?,
                None => None,
            };

            if !holds_state && evicted.as_ref().is_none_or(Vec::is_empty) {
                // Nothing of the target here at all: nothing recorded, no
                // state, nothing listed (they left between the gate and here).
                // The end state already holds, so this answers 200 and runs no
                // script, the skip `remove_user_from_voice_channel` makes.
                log::info!(
                    "voice disconnect of {} from {}: nothing recorded, listed or held there; \
                     already out",
                    target_user.id,
                    channel
                );
            } else {
                // 3. `returned ∪ (recorded − returned)`: every sid the
                //    eviction returned, then every sid recorded BEFORE the
                //    listing that it did not list (stale), each once. With no
                //    listing (no node, or no room), the recorded sids alone.
                //    An EMPTY set is the script's pure survivor check: with
                //    nothing of the target recorded it is `Last` and the full
                //    teardown, which a legacy connection or a ghost with state
                //    and no record needs. A connection recorded after step 1
                //    that the listing did not see is in neither set, so the
                //    script answers `Survivor` and it keeps its state. The
                //    database crate's shared teardown does all of it, and
                //    publishes the `VoiceChannelLeave` of a `Last` that no
                //    webhook will announce (nothing evicted: a ghost of an
                //    ended call), which this route used to leave on every
                //    roster (AFK S-3 WB-8).
                tear_down_removed_connections(&uvc, &target_user.id, evicted, recorded).await?;
            }
        }
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
            create_voice_state, delete_channel_voice_state, get_user_voice_channel_in_server,
            get_voice_channel_members, get_voice_state, is_in_voice_channel,
            record_voice_connection, recorded_voice_connections, set_channel_node,
            update_voice_state, UserVoiceChannel, MAX_VIDEO_PARTICIPANTS,
        },
        Channel, Member, MlsGroup, MlsGroupCreateOutcome, MlsMemberDevice, PartialServer, Server,
        User, MAX_MLS_GROUP_MEMBERS,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
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
                spoiler: None,
                voice: Some(v0::VoiceInformation {
                    max_users: None,
                    disabled: false,
                }),
                announcement: None,
                ..Default::default()
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
    /// Deliberately NOT a node in `Revolt.toml`: every `VoiceClient` SFU call
    /// (the sync's listing and pushes, the disconnect's eviction) resolves the
    /// node name through `get_node` before it touches the network, so an
    /// unknown one turns the unreachable-SFU call into an immediate
    /// `UnknownNode` instead of a ~25s DNS/connect stall (today's
    /// `SFU_CALL_TIMEOUT` would cut that to 3 s, still on every call) — which
    /// sat right on nextest's 50s kill threshold.
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

    // ---- the move expects the gated source (AFK Stage 6 F-A3, pure) -------

    /// `edit`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("member_edit.rs");
        let at = SOURCE
            .find("pub async fn edit(")
            .expect("the route is defined");
        let open = at + SOURCE[at..].find('\u{7b}').expect("a body");
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in SOURCE[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        SOURCE[open..=close.expect("a closed body")]
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The source-side gate decides about the channel it read; the move must
    /// act on that same channel. A move that re-derives the source from the
    /// pointer pulls a target who switched channels in between out of a
    /// channel the mover was never authorized over. Pinned here: one pointer
    /// read before the move (the gated one), the `NotConnected` precondition
    /// answered from it, and the move EXPECTING it, exactly once. Mutations:
    /// a fresh pointer read in place of the gated source, or a second move
    /// call. (The S-3 cleanup made the expectation a required `&str`, so a
    /// `None` expectation and the plain move no longer compile; the ban on
    /// the plain move that used to sit here went vacuous and is retargeted
    /// at the move's call count.)
    #[test]
    fn the_move_expects_the_source_the_mover_was_gated_on() {
        const READ: &str = "let source_id = \
             get_user_voice_channel_in_server(&target_user.id, &server.id).await?;";
        const GATE: &str = "if let Some(source_id) = &source_id \u{7b} \
             let source = Reference::from_unchecked(source_id).as_channel(db).await?; \
             if member.id.user != user.id \u{7b} \
             assert_mover_may_move_out_of(db, &user, &source).await?; \u{7d} \u{7d}";
        const CARRY: &str = "let Some(source_id) = source_id.clone() else \u{7b} \
             return Err(create_error!(NotConnected)); \u{7d}; \
             Some((channel, source_id))";
        const MOVE: &str = "if let Some((new_voice_channel, source_id)) = new_voice_channel \
             \u{7b} match move_user_to_voice_channel_expecting( db, voice_client, &target_user, \
             &new_voice_channel, &source_id, ) .await? \u{7b}";

        let body = route_body();
        let mut last = 0;
        for needle in [READ, GATE, CARRY, MOVE] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the route must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last <= at, "`{}` is out of order: {}", needle, body);
            last = at;
        }

        assert_eq!(
            body.matches("move_user_to_voice_channel_expecting(")
                .count(),
            1,
            "the route moves once, from the gated source: {}",
            body
        );
        assert_eq!(
            body[..last]
                .matches("get_user_voice_channel_in_server(")
                .count(),
            1,
            "the move path must read the pointer once, in the gate: a second \
             read can name a channel the mover was never checked against: {body}"
        );
    }

    /// AFK Stage 6 FU-C: a move that did not happen is never a 2xx. The
    /// outcome is matched exhaustively; `NotConnected` (the target left or
    /// switched away from the gated source after the precondition) answers
    /// the same `NotConnected` error the precondition gives, and only
    /// `Moved` / `AlreadyPresent` fall through to the 200. Mutations: the
    /// `NotConnected` arm turned into `{}`, a `_ => {}` catch-all, or the
    /// outcome dropped again with `.await?;`.
    #[test]
    fn a_move_that_did_not_happen_is_an_error() {
        const OUTCOME: &str = "&source_id, ) .await? \u{7b} \
             VoiceMoveOutcome::Moved \u{7b} .. \u{7d} | VoiceMoveOutcome::AlreadyPresent => \u{7b}\u{7d} \
             VoiceMoveOutcome::NotConnected => return Err(create_error!(NotConnected)), \u{7d}";

        let body = route_body();
        assert_eq!(
            body.matches(OUTCOME).count(),
            1,
            "the move's outcome must be matched, with `NotConnected` an error: {body}"
        );
        assert_eq!(
            body.matches("VoiceMoveOutcome::").count(),
            3,
            "exactly the three variants, no catch-all: {body}"
        );
    }

    /// AFK Stage 6 FU-B: the disconnect shape removes the target from the
    /// channel the source-side gate decided about, never from a fresh read.
    /// A fresh read here could name a call the target switched to after the
    /// gate, and the mover would kick them out of a channel they were never
    /// checked against.
    ///
    /// AFK S-3 F-13 (D-2, amended by WA-R / RA2-1): inside that block, the
    /// recorded connections are read BEFORE the one SFU listing (a read after
    /// it deletes a sibling that recorded in between, WA-1), a failed read or
    /// a failed eviction is returned before anything is torn down, and the
    /// teardown deletes exactly `returned ∪ (recorded − returned)` in set
    /// mode, never the whole-user `delete_voice_state`. The remote-control
    /// release keeps its reason and still precedes the eviction.
    ///
    /// Mutations: the fresh read put back; the release or the eviction
    /// addressed to anything but the gated source; the recorded read moved
    /// after the eviction; a `?` dropped from the recorded read or the
    /// eviction; the set delete replaced by `delete_voice_state`.
    ///
    /// AFK S-3 cleanup (WB-6, WB-8): the presence check is the database
    /// crate's `holds_voice_state_in` (the per-server pointer included) and
    /// the teardown its `tear_down_removed_connections`, which also publishes
    /// the Leave no webhook will. A bare `delete_voice_connections(` here
    /// would skip that Leave, so it is banned. The vacuous `.remove_user(`
    /// ban (the method is deleted) is gone from the list, and the route-wide
    /// one is retargeted at the whole-user `delete_voice_state(`.
    #[test]
    fn the_disconnect_removes_from_the_gated_source_only() {
        const OPEN: &str = "if remove.contains(&FieldsMember::VoiceChannel) \u{7b}";
        const SOURCE: &str = "if let Some(channel) = &source_id \u{7b} \
             let uvc = UserVoiceChannel \u{7b} id: channel.clone(), \
             server_id: Some(server.id.clone()), \u{7d};";
        const RECORDED: &str = "let recorded: Vec<String> = \
             recorded_voice_connections(&uvc, &target_user.id) .await? \
             .into_iter() .map(|(sid, _)| sid) .collect();";
        const HOLDS: &str = "let holds_state = !recorded.is_empty() \
             || holds_voice_state_in(&uvc, &target_user.id).await?;";
        const NODE: &str = "let node = get_channel_node(channel).await?;";
        const RELEASE: &str = "release_remote_control_for_user( db, voice_client, &uvc, \
             &target_user.id, \"revoked_by_moderator\", false, ) .await;";
        const EVICT: &str = "let evicted = match &node \u{7b} Some(node) => voice_client \
             .remove_user_if_present_sids(node, &target_user.id, channel) .await \
             .map_err(EvictionFailure::into_error)?, None => None, \u{7d};";
        const SKIP: &str = "if !holds_state && evicted.as_ref().is_none_or(Vec::is_empty) \u{7b}";
        const TEARDOWN: &str =
            "tear_down_removed_connections(&uvc, &target_user.id, evicted, recorded).await?;";

        let body = route_body();
        assert_eq!(body.matches(OPEN).count(), 1, "{body}");
        let open = body.find(OPEN).expect("counted above") + OPEN.len() - 1;
        let mut depth = 0usize;
        let mut close = None;
        for (i, ch) in body[open..].char_indices() {
            match ch {
                '\u{7b}' => depth += 1,
                '\u{7d}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let block = &body[open..=close.expect("the disconnect block closes")];

        let mut last = 0;
        for needle in [
            SOURCE, RECORDED, HOLDS, NODE, RELEASE, EVICT, SKIP, TEARDOWN,
        ] {
            assert_eq!(
                block.matches(needle).count(),
                1,
                "the disconnect must carry `{needle}` exactly once: {block}"
            );
            let at = block.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, block);
            last = at;
        }
        for banned in [
            "get_user_voice_channel_in_server(",
            "delete_voice_state(",
            "delete_voice_connections(",
            "remove_user_if_present(",
            "remove_user_from_voice_channel(",
        ] {
            assert!(
                !block.contains(banned),
                "the disconnect must not call `{}`: {}",
                banned,
                block
            );
        }
        assert_eq!(
            block.matches("remove_user_if_present_sids(").count(),
            1,
            "one eviction, from the gated source: {block}"
        );
        assert!(
            !body.contains("delete_voice_state("),
            "no whole-user voice-state teardown anywhere in the route: {}",
            body
        );
    }

    /// AFK S-3 L-a: a call that ends mid-request leaves no node behind the
    /// channel, and the sync path used to `unwrap` that read and panic. No
    /// node read in the route may be unwrapped. Each `get_channel_node(` is
    /// read up to the end of its statement or the brace that opens its
    /// block. Mutation: the `.unwrap()` put back on the sync path.
    #[test]
    fn no_node_read_in_the_route_is_unwrapped() {
        let body = route_body();
        let reads: Vec<&str> = body
            .match_indices("get_channel_node(")
            .map(|(at, _)| {
                let rest = &body[at..];
                let end = rest
                    .find(|ch: char| ch == ';' || ch == '\u{7b}')
                    .unwrap_or(rest.len());
                &rest[..end]
            })
            .collect();
        assert_eq!(
            reads.len(),
            2,
            "the sync path and the disconnect each read the node once: {body}"
        );
        for read in reads {
            assert!(
                !read.contains(".unwrap()") && !read.contains(".expect("),
                "a node read must answer `None` as a no-op, never unwrap it: {}",
                read
            );
        }
    }

    // ---- what the move refuses past the caps gate ------------------------
    //
    // Until these, nothing exercised the move beyond `assert_call_caps_admit`
    // — both move tests above stop there, and the `voice_channel` fixture is a
    // real voice channel, which is why the destination was never checked to be
    // one at all.
    //
    // ---- behavior (needs RabbitMQ and Redis) ------------------------------
    //
    // Compile-only on a box without those services: `TestHarness::new`
    // connects to RabbitMQ and the voice state lives in Redis (and, under
    // `TEST_DB=MONGODB`, the documents in MongoDB), so each test in this
    // section fails before it asserts anything there, like every other route
    // test in this crate. Each carries the one-line label below as well.

    /// A voice channel with an explicit occupancy cap.
    async fn capped_voice_channel(
        harness: &TestHarness,
        server: &Server,
        name: &str,
        max_users: usize,
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
                    max_users: Some(max_users),
                    disabled: false,
                }),
                announcement: None,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("capped voice channel")
    }

    async fn text_channel(harness: &TestHarness, server: &Server, name: &str) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            &mut server.clone(),
            v0::DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: name.to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: None,
                announcement: None,
                ..Default::default()
            },
            true,
        )
        .await
        .expect("text channel")
    }

    async fn assert_rejected(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        error_type: &str,
    ) {
        assert_eq!(response.status(), status);
        let body = response.into_string().await.unwrap();
        assert!(
            body.contains(error_type),
            "expected the move to be refused with {}, got {}",
            error_type,
            body
        );
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn move_into_a_text_channel_is_refused() {
        crate::util::test::rt().block_on(move_into_a_text_channel_is_refused_case())
    }

    async fn move_into_a_text_channel_is_refused_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let text = text_channel(&harness, &server, "General").await;
        let source_uvc = connect_publishing(&source, &user_b.id).await;

        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            text.id(),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "NotAVoiceChannel").await;

        delete_channel_voice_state(&source_uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn move_is_refused_when_the_target_lacks_connect() {
        crate::util::test::rt().block_on(move_is_refused_when_the_target_lacks_connect_case())
    }

    async fn move_is_refused_when_the_target_lacks_connect_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // moderator = owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let mut destination = voice_channel(&harness, &server, "Restricted").await;
        let source_uvc = connect_publishing(&source, &user_b.id).await;

        // Deny Connect to the default role on the DESTINATION. The moderator
        // is the server owner, so the permission calculus short-circuits to
        // GrantAllSafe for them before this override is ever read — which is
        // precisely why a mover-side Connect check cannot catch this.
        destination
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::Connect as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny connect");

        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            destination.id(),
        )
        .await;
        assert_rejected(response, Status::Forbidden, "MissingPermission").await;

        delete_channel_voice_state(&source_uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn move_is_refused_when_the_mover_is_denied_the_destination() {
        crate::util::test::rt()
            .block_on(move_is_refused_when_the_mover_is_denied_the_destination_case())
    }

    /// The mover's own standing on the DESTINATION, which the server-scoped
    /// `MoveMembers` check cannot see.
    ///
    /// The moderator here is not the owner — the calculus short-circuits to
    /// GrantAllSafe for an owner before any override is read, so the gate is
    /// unpinnable with one. They hold `MoveMembers` from a server role, and
    /// the destination denies that same role `ViewChannel`. Server-scoped,
    /// that is a pass; channel-scoped, it is a refusal. Without the
    /// channel-scoped gate a moderator locked out of a private voice channel
    /// could still pull anybody into it, out of the call they were in.
    async fn move_is_refused_when_the_mover_is_denied_the_destination_case() {
        use std::collections::HashMap;

        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // moderator
        let (_c, _session_c, user_c) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        for user in [&user_b, &user_c] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        // The moderator holds MoveMembers at the SERVER level.
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::MoveMembers as i64,
                    d: 0,
                }),
            )
            .await;
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "roles": [role.id] }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok, "owner may assign the role");

        let source = voice_channel(&harness, &server, "Source").await;
        let mut destination = voice_channel(&harness, &server, "Private").await;
        let source_uvc = connect_publishing(&source, &user_c.id).await;

        // Control, before the channel override: the same moderator, the same
        // target, the same destination — the request walks past every
        // admission gate and dies at the deliberately absent node. So the
        // refusal below is the override doing the work, not the fixture.
        let response = move_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            destination.id(),
        )
        .await;
        let body = response.into_string().await.unwrap();
        assert!(
            body.contains("UnknownNode"),
            "control: the mover must be admitted before the override, got {}",
            body
        );

        // The destination denies the moderator's role. The TARGET's own
        // standing is untouched — they are on the default role, which this
        // override says nothing about — so a refusal here can only be the
        // mover-side gate.
        destination
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    role_permissions: Some(HashMap::from([(
                        role.id.clone(),
                        OverrideField {
                            a: 0,
                            d: ChannelPermission::ViewChannel as i64,
                        },
                    )])),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny the role on the destination");

        let response = move_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            destination.id(),
        )
        .await;
        assert_rejected(response, Status::Forbidden, "MissingPermission").await;

        // ...and the target is still where they were.
        assert!(
            is_publishing(&source_uvc, &user_c.id).await,
            "a refused move must leave the target in their original call"
        );

        delete_channel_voice_state(&source_uvc, &[user_c.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn moving_a_member_to_the_channel_they_are_in_is_a_no_op() {
        crate::util::test::rt()
            .block_on(moving_a_member_to_the_channel_they_are_in_is_a_no_op_case())
    }

    async fn moving_a_member_to_the_channel_they_are_in_is_a_no_op_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        // CAPPED AND FULL, with the member themselves as the occupant that
        // fills it. The fixture used to be uncapped, which is the only reason
        // this test passed while the occupancy cap was still decided ahead of
        // the "already there" answer: `1 >= 1` refused the member for
        // occupying the very channel they were being moved into, so the route
        // 400'd on a no-op and the AFK sweep refused every occupant of a full
        // AFK channel on every tick.
        let channel = capped_voice_channel(&harness, &server, "Voice", 1).await;
        let uvc = connect_publishing(&channel, &user_b.id).await;

        // Source == destination. The observable is ABSENT_NODE: every LiveKit
        // call this route can make resolves its node name first and raises
        // UnknownNode, so reaching the move machinery at all cannot return
        // 200. A 200 therefore proves nothing was created, no token was
        // minted and — the point — no eviction ever ran against the room
        // the member is already sitting in. Left unguarded this is what makes
        // an AFK sweep re-kick the whole AFK channel on every tick.
        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            channel.id(),
        )
        .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "moving a member into the channel they are already in must do nothing"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn move_into_a_full_channel_is_refused_unless_the_target_manages_it() {
        crate::util::test::rt()
            .block_on(move_into_a_full_channel_is_refused_unless_the_target_manages_it_case())
    }

    async fn move_into_a_full_channel_is_refused_unless_the_target_manages_it_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let source_uvc = connect_publishing(&source, &user_b.id).await;

        let full = capped_voice_channel(&harness, &server, "Full", 1).await;
        let full_uvc = UserVoiceChannel::from_channel(&full);
        let occupant = "0CAPOCCUPANT00000000000000".to_string();
        create_voice_state(&full_uvc, &occupant, Timestamp::now_utc())
            .await
            .expect("occupant");

        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            full.id(),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "CannotJoinCall").await;

        // Same cap, same single occupant — but the TARGET holds ManageChannel
        // here, which is the exemption the join front door grants. The
        // exemption is read off the target's permissions, not the mover's:
        // the mover is the owner and would be exempt either way.
        let mut managed = capped_voice_channel(&harness, &server, "FullManaged", 1).await;
        let managed_uvc = UserVoiceChannel::from_channel(&managed);
        create_voice_state(&managed_uvc, &occupant, Timestamp::now_utc())
            .await
            .expect("occupant");
        managed
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: ChannelPermission::ManageChannel as i64,
                        d: 0,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("grant manage channel");

        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            managed.id(),
        )
        .await;
        // `CannotJoinCall` and `UnknownNode` are both 400, so the status alone
        // proves nothing here: assert on which one. Reaching UnknownNode means
        // the request walked past every admission gate and died at the
        // deliberately unreachable node these tests pin their channels to.
        let body = response.into_string().await.unwrap();
        assert!(
            !body.contains("CannotJoinCall") && body.contains("UnknownNode"),
            "a ManageChannel holder is exempt from the occupancy cap, as they \
             are at the join front door — expected the request to reach the \
             absent node, got {}",
            body
        );

        delete_channel_voice_state(&source_uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup source");
        delete_channel_voice_state(&full_uvc, &[occupant.clone()])
            .await
            .expect("cleanup full");
        delete_channel_voice_state(&managed_uvc, &[occupant])
            .await
            .expect("cleanup managed");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn move_is_refused_when_the_mover_is_denied_the_source() {
        crate::util::test::rt().block_on(move_is_refused_when_the_mover_is_denied_the_source_case())
    }

    /// The mover's own standing on the SOURCE — the call the target is being
    /// pulled out of — which nothing checked at all.
    ///
    /// Same construction as the destination test, and for the same reason the
    /// moderator is not the owner: the calculus short-circuits to GrantAllSafe
    /// for an owner before any override is read. They hold `MoveMembers` from
    /// a server role and the SOURCE denies that role `ViewChannel`. Server
    /// scoped that is a pass; channel-scoped it is a refusal. Without the
    /// gate, a moderator explicitly locked out of a private voice channel can
    /// empty it into a channel they do control, and can enumerate who was in
    /// it by telling `NotConnected` apart from a success.
    ///
    /// Both shapes that reach into the source are covered: the move, and the
    /// `remove: ["VoiceChannel"]` disconnect.
    async fn move_is_refused_when_the_mover_is_denied_the_source_case() {
        use std::collections::HashMap;

        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // moderator
        let (_c, _session_c, user_c) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        for user in [&user_b, &user_c] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        // The moderator holds MoveMembers at the SERVER level.
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: ChannelPermission::MoveMembers as i64,
                    d: 0,
                }),
            )
            .await;
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "roles": [role.id] }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok, "owner may assign the role");

        let mut source = voice_channel(&harness, &server, "Private").await;
        let destination = voice_channel(&harness, &server, "Dest").await;
        let source_uvc = connect_publishing(&source, &user_c.id).await;

        // Control, before the channel override: the same moderator, the same
        // target, the same source — the request walks past every gate and dies
        // at the deliberately absent node. So the refusal below is the
        // override doing the work, not the fixture.
        let response = move_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            destination.id(),
        )
        .await;
        let body = response.into_string().await.unwrap();
        assert!(
            body.contains("UnknownNode"),
            "control: the mover must be admitted before the override, got {}",
            body
        );

        // The SOURCE denies the moderator's role. The destination is
        // untouched, and so is the target's own standing, so a refusal here
        // can only be the source-side gate.
        source
            .update(
                &harness.db,
                revolt_database::PartialChannel {
                    role_permissions: Some(HashMap::from([(
                        role.id.clone(),
                        OverrideField {
                            a: 0,
                            d: ChannelPermission::ViewChannel as i64,
                        },
                    )])),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("deny the role on the source");

        let response = move_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            destination.id(),
        )
        .await;
        assert_rejected(response, Status::Forbidden, "MissingPermission").await;

        // The disconnect shape reaches into the same channel and is refused
        // the same way — it used to run its eviction with no
        // channel-scoped check of the acting user anywhere.
        let response = edit_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            serde_json::json!({ "remove": ["VoiceChannel"] }),
        )
        .await;
        assert_rejected(response, Status::Forbidden, "MissingPermission").await;

        // ...and the target is still where they were, in both cases.
        assert!(
            is_publishing(&source_uvc, &user_c.id).await,
            "a refused move must leave the target in their original call"
        );

        delete_channel_voice_state(&source_uvc, &[user_c.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn moving_and_editing_roles_in_one_patch_is_refused() {
        crate::util::test::rt().block_on(moving_and_editing_voice_permissions_case(|dest| {
            vec![
                serde_json::json!({ "voice_channel": dest, "roles": [] }),
                serde_json::json!({ "voice_channel": dest, "remove": ["Roles"] }),
            ]
        }))
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn moving_and_editing_the_timeout_in_one_patch_is_refused() {
        crate::util::test::rt().block_on(moving_and_editing_voice_permissions_case(|dest| {
            let until = Timestamp::now_utc()
                .checked_add(Duration::hours(1))
                .expect("timeout timestamp");
            vec![
                serde_json::json!({ "voice_channel": dest, "timeout": until }),
                serde_json::json!({ "voice_channel": dest, "remove": ["Timeout"] }),
            ]
        }))
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn moving_and_muting_or_deafening_in_one_patch_is_refused() {
        crate::util::test::rt().block_on(moving_and_editing_voice_permissions_case(|dest| {
            vec![
                serde_json::json!({ "voice_channel": dest, "can_publish": false }),
                serde_json::json!({ "voice_channel": dest, "can_receive": false }),
            ]
        }))
    }

    /// A move is decided twice — once side-effect free before the member
    /// document is written, once inside the move itself afterwards, against
    /// the member as they now stand. Combined with an edit that changes those
    /// very permissions the two readings disagree, and the disagreement is
    /// observable in both directions: grant-and-move is refused on pre-edit
    /// permissions, and timeout-and-move applies the timeout and then refuses
    /// the move, leaving a half-applied edit behind. Refusing the combination
    /// is what makes the route's ordering guarantee true.
    ///
    /// Split three ways (AFK Stage 6 FU-A). The `servers` ratelimit bucket
    /// allows 5 requests per window per user and server, and it is kept per
    /// Rocket instance, i.e. per `TestHarness`. The six bodies used to go
    /// through one moderator on one server, and the sixth was answered 429
    /// before it reached the route. Each test now sends two bodies plus the
    /// control, three requests, on its own harness. The refusal is asserted
    /// by ERROR TYPE as well as status: `UnknownNode`, which a move that got
    /// past the refusal reaches, is also a 400.
    async fn moving_and_editing_voice_permissions_case(
        bodies: impl FnOnce(&str) -> Vec<serde_json::Value>,
    ) {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await;
        let (_b, _session_b, user_b) = harness.new_user().await;
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let destination = voice_channel(&harness, &server, "Dest").await;
        let source_uvc = connect_publishing(&source, &user_b.id).await;

        for body in bodies(destination.id()) {
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
                "{body} moves the member and changes the permissions the move \
                 is decided under, and must be refused"
            );
            let error = response.into_string().await.unwrap_or_default();
            assert!(
                error.contains("InvalidOperation"),
                "{} must be refused as InvalidOperation, got {}",
                body,
                error
            );
        }

        // Nothing was applied on the way to any of those refusals.
        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(member.can_publish);
        assert!(member.can_receive);
        assert!(member.timeout.is_none(), "no timeout may survive a refusal");

        // A move on its own is untouched by the refusal — it reaches the
        // deliberately absent node, which is well past every gate above.
        let response = move_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            destination.id(),
        )
        .await;
        let body = response.into_string().await.unwrap();
        assert!(
            body.contains("UnknownNode"),
            "a move by itself must still be admitted, got {}",
            body
        );

        delete_channel_voice_state(&source_uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // ---- the disconnect's teardown (AFK S-3 F-13) ------------------------
    //
    // No SFU is reachable from here (the database crate's stub SFU is
    // test-only inside that crate), so these drive the arms decided without
    // a listing: no node pinned (a ghost of a call that has ended), and
    // ABSENT_NODE, whose unknown name fails the eviction before any network.
    // The listed arms are text-pinned in
    // `the_disconnect_removes_from_the_gated_source_only`.

    /// Every trace of `user_id` in `uvc` the teardown owns: the recorded
    /// connections, `vc:` membership, `vc_members:` membership, and the
    /// per-server pointer when it names this channel.
    async fn voice_traces(
        uvc: &UserVoiceChannel,
        user_id: &str,
    ) -> (Vec<(String, String)>, bool, bool, bool) {
        let recorded = recorded_voice_connections(uvc, user_id)
            .await
            .expect("recorded read");
        let listed = is_in_voice_channel(user_id, uvc).await.expect("vc read");
        let member = get_voice_channel_members(uvc)
            .await
            .expect("members read")
            .is_some_and(|members| members.iter().any(|id| id == user_id));
        let pointer = get_user_voice_channel_in_server(
            user_id,
            uvc.server_id.as_deref().expect("a server channel"),
        )
        .await
        .expect("pointer read")
        .as_deref()
            == Some(uvc.id.as_str());
        (recorded, listed, member, pointer)
    }

    /// A join as voice-ingress records it: the connection first, then the
    /// state, created only for the user's first connection.
    async fn join_recorded(uvc: &UserVoiceChannel, user_id: &str, sid: &str, identity: &str) {
        if record_voice_connection(uvc, user_id, sid, identity)
            .await
            .expect("record")
        {
            create_voice_state(uvc, user_id, Timestamp::now_utc())
                .await
                .expect("voice state");
        }
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn disconnecting_a_ghost_of_an_ended_call_clears_it() {
        crate::util::test::rt().block_on(disconnecting_a_ghost_of_an_ended_call_clears_it_case())
    }

    /// A call that ended without its webhooks (no node pinned any more)
    /// leaves the target on the roster. The disconnect used to be a no-op
    /// here. It now tears down from the recorded sids, as
    /// `remove_user_from_voice_channel` does: every recorded connection, two
    /// of them here, and a legacy state with no record at all (the empty set,
    /// which the script answers `Last`). Mutations: the recorded sids dropped
    /// from the set (the records survive, so the script answers `Survivor`
    /// and tears nothing down); the teardown skipped.
    ///
    /// AFK S-3 WB-8: each teardown publishes the target's
    /// `VoiceChannelLeave` on the channel's topic. No node is pinned, so no
    /// connection is evicted and no `participant_left` webhook will ever
    /// announce it; without this every other client kept the ghost.
    /// Mutation: the Leave dropped from the shared teardown (the wait times
    /// out).
    async fn disconnecting_a_ghost_of_an_ended_call_clears_it_case() {
        let mut harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // recorded ghost
        let (_c, _session_c, user_c) = harness.new_user().await; // legacy ghost
        let (server, _channels) = harness.new_server(&user_a).await;
        for user in [&user_b, &user_c] {
            Member::create(&harness.db, &server, user, None)
                .await
                .expect("member");
        }

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_ghost_bare", &user_b.id).await;
        join_recorded(
            &uvc,
            &user_b.id,
            "PA_ghost_device",
            &format!("{}:DEV", user_b.id),
        )
        .await;
        create_voice_state(&uvc, &user_c.id, Timestamp::now_utc())
            .await
            .expect("legacy voice state");

        // The fixture holds what it claims to, and no node is pinned.
        let (recorded, listed, member, pointer) = voice_traces(&uvc, &user_b.id).await;
        assert_eq!(recorded.len(), 2, "two recorded connections");
        assert!(listed && member && pointer, "the recorded ghost has state");
        let (recorded, listed, member, pointer) = voice_traces(&uvc, &user_c.id).await;
        assert!(recorded.is_empty(), "the legacy ghost has no record");
        assert!(listed && member && pointer, "the legacy ghost has state");
        assert!(
            revolt_database::voice::get_channel_node(channel.id())
                .await
                .expect("node read")
                .is_none(),
            "the call has ended: no node"
        );

        for target in [&user_b, &user_c] {
            let response = edit_member(
                &harness,
                &session_a.token,
                &server.id,
                &target.id,
                serde_json::json!({ "remove": ["VoiceChannel"] }),
            )
            .await;
            assert_eq!(
                response.status(),
                Status::Ok,
                "disconnecting a ghost of an ended call is a success"
            );
            // The response borrows the harness, which the event wait needs.
            drop(response);

            let (recorded, listed, member, pointer) = voice_traces(&uvc, &target.id).await;
            assert!(
                recorded.is_empty() && !listed && !member && !pointer,
                "the ghost of {} must be torn down, left: recorded {:?}, vc {}, \
                 vc_members {}, pointer {}",
                target.id,
                recorded,
                listed,
                member,
                pointer
            );

            harness
                .wait_for_event(channel.id(), |event| {
                    matches!(
                        event,
                        EventV1::VoiceChannelLeave { id, user }
                            if id == channel.id() && user == &target.id
                    )
                })
                .await;
        }

        delete_channel_voice_state(&uvc, &[user_b.id.clone(), user_c.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn disconnecting_a_pointer_only_ghost_clears_it() {
        crate::util::test::rt().block_on(disconnecting_a_pointer_only_ghost_clears_it_case())
    }

    /// AFK S-3 WB-6: the disconnect's skip is the database crate's own
    /// presence check, which counts the per-server pointer too. A target
    /// whose ONLY trace in the gated channel is the pointer (and the flags
    /// keyed by it; no record, no `vc:`, no `vc_members:`) used to be skipped
    /// as "already out", leaving the pointer that still names the channel.
    /// The pointer is also what the gate read, so the gated source IS that
    /// channel. Now it is torn down (the empty set, `Last`), and, with no
    /// node and so no webhook, its Leave is published (WB-8). Mutation: the
    /// pointer dropped from `holds_voice_state_in` (the pointer stays).
    async fn disconnecting_a_pointer_only_ghost_clears_it_case() {
        use redis_kiss::AsyncCommands;

        let mut harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Pointer").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        // Keep the pointer and its flags, drop both roster memberships.
        let mut conn = redis_kiss::get_connection().await.expect("redis");
        conn.srem::<_, _, ()>(format!("vc_members:{}", uvc.id), &user_b.id)
            .await
            .expect("srem vc_members");
        conn.srem::<_, _, ()>(format!("vc:{}", user_b.id), uvc.to_string())
            .await
            .expect("srem vc");

        let (recorded, listed, member, pointer) = voice_traces(&uvc, &user_b.id).await;
        assert!(
            recorded.is_empty() && !listed && !member && pointer,
            "the fixture is a pointer-only ghost: recorded {:?}, vc {}, vc_members {}, \
             pointer {}",
            recorded,
            listed,
            member,
            pointer
        );
        assert!(
            revolt_database::voice::get_channel_node(channel.id())
                .await
                .expect("node read")
                .is_none(),
            "the call has ended: no node"
        );

        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "remove": ["VoiceChannel"] }),
        )
        .await;
        assert_eq!(response.status(), Status::Ok);
        // The response borrows the harness, which the event wait needs.
        drop(response);

        let (_, _, _, pointer) = voice_traces(&uvc, &user_b.id).await;
        let state = get_voice_state(&uvc, &user_b.id).await.expect("state read");
        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");

        assert!(
            !pointer,
            "the pointer naming the gated source must be torn down"
        );
        assert!(
            state.is_none(),
            "the flags keyed by it go with it: {:?}",
            state
        );
        harness
            .wait_for_event(channel.id(), |event| {
                matches!(
                    event,
                    EventV1::VoiceChannelLeave { id, user }
                        if id == channel.id() && user == &user_b.id
                )
            })
            .await;
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_failed_disconnect_eviction_tears_nothing_down() {
        crate::util::test::rt().block_on(a_failed_disconnect_eviction_tears_nothing_down_case())
    }

    /// An eviction that fails may have left a listed connection live, so the
    /// error is answered and NOTHING is torn down: the target stays visible
    /// and syncable. ABSENT_NODE makes the eviction fail with `UnknownNode`
    /// before any network. Mutation: the eviction's error swallowed (the
    /// teardown then runs from the recorded sids and answers 200).
    async fn a_failed_disconnect_eviction_tears_nothing_down_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Live").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_live", &user_b.id).await;
        set_channel_node(channel.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "remove": ["VoiceChannel"] }),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "UnknownNode").await;

        let (recorded, listed, member, pointer) = voice_traces(&uvc, &user_b.id).await;
        assert_eq!(
            recorded,
            vec![("PA_live".to_string(), user_b.id.clone())],
            "a failed eviction must leave the record in place"
        );
        assert!(
            listed && member && pointer,
            "a failed eviction must leave the voice state in place: vc {}, \
             vc_members {}, pointer {}",
            listed,
            member,
            pointer
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_voice_sync_after_the_call_ended_is_a_no_op() {
        crate::util::test::rt().block_on(a_voice_sync_after_the_call_ended_is_a_no_op_case())
    }

    /// AFK S-3 L-a: the target's pointer names a channel whose call has ended
    /// (no node), as when the call ends mid-request. The sync has nobody to
    /// reach and the edit is already written, so the answer is 200. The node
    /// read used to be unwrapped and panicked the request. Mutation: the
    /// `.unwrap()` put back.
    async fn a_voice_sync_after_the_call_ended_is_a_no_op_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        create_voice_state(&uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");

        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            serde_json::json!({ "can_publish": false }),
        )
        .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "a mute whose call has ended must still be applied, and answered 200"
        );

        let member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .expect("member read");
        assert!(!member.can_publish, "the mute is written");

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }
}
