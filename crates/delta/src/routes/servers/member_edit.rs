use std::collections::HashSet;

use revolt_database::{
    util::{
        name_filter::contains_blocked_slur, permissions::DatabasePermissionQuery,
        reference::Reference,
    },
    voice::{
        assert_voice_move_admissible, drop_voice_participant_session, get_channel_node,
        get_user_voice_channel_in_server, get_voice_participant_session, holds_voice_state_in,
        move_user_to_voice_channel_expecting, recorded_voice_connections,
        self_move_from_owning_session, sync_user_voice_permissions, tear_down_removed_connections,
        EvictionFailure, MovePolicy, UserVoiceChannel, VoiceClient, VoiceMoveOutcome,
    },
    Channel, Database, File, PartialMember, Session, User,
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
/// `MoveMembers` is decided per channel, on the two channels a move touches
/// (ruling D0-3): here for the destination, `assert_mover_may_move_out_of` for
/// the source. The server-scoped check (computed from
/// `DatabasePermissionQuery::new(db, &user).server(&server)`, which never reads
/// a channel override) is only the fallback for a target in no call at all
/// (or in a call hidden from the mover, which the route treats as no call).
/// Server-scoped, a role that holds `MoveMembers` at the server level would
/// pass even on a private voice channel whose overrides deny that role
/// outright, and the privileged door would be wider than the front door: a
/// moderator who cannot see or enter a channel could still pull anybody into
/// it.
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
///
/// `Connect` too (ruling 09-27): a moderator may only pull somebody into a
/// channel they could join themselves. The TARGET needs no Connect for a
/// moderator's move (ruling D0-1), so this is the only Connect a moderator
/// move asks for. Checked after `MoveMembers`, so a mover who lacks both is
/// told about `MoveMembers`.
async fn assert_mover_may_move_into(
    db: &Database,
    user: &User,
    destination: &Channel,
) -> Result<()> {
    let mut query = DatabasePermissionQuery::new(db, user).channel(destination);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;

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
/// channel they do control.
///
/// Applies to the disconnect shape (`remove: ["VoiceChannel"]`) as well as
/// the move: kicking somebody out of a call is the same reach into the same
/// channel, minus a destination. That is why the call site sits in the block
/// both shapes pass through rather than inside the move branch.
///
/// Only ever asked about a source the mover can SEE (operator ruling
/// 2026-09-28, merge slice FXA-1). The mover does not name the source: it
/// is wherever the target happens to be, so anything decided about it is an
/// answer about the target. A refusal from this gate for a call hidden from
/// the mover would tell them the target sits in it: a 403 where a target in
/// no call gets the no-source fallback's answer (for a mover holding
/// `MoveMembers` server-wide, a 200 no-op for a disconnect and
/// `NotConnected` for a move). So the route treats a target in a call the
/// mover cannot see as in NO call before this gate is reached (see
/// `mover_can_see_source` and the call site). That, not this gate, is what
/// keeps a hidden call from being enumerated, whatever the mover holds.
///
/// `ViewChannel` and `MoveMembers` both, deliberately, and neither costs a
/// legitimate flow. A moderator holding `MoveMembers` at the server level
/// keeps it in every channel that does not explicitly deny it, so the only
/// request this refuses is one an override was written to refuse.
/// `ViewChannel` refuses nothing here any more (the call site has already
/// asked it); it states the rule (you cannot reach into a channel you cannot
/// see) and keeps the gate correct if the call site ever stops asking.
///
/// `MoveMembers` is asked FIRST (merge slice M2C-1). A mover who holds
/// `MoveMembers` nowhere is refused `MissingPermission` for `MoveMembers` by
/// the route's no-source fallback when the target is in no call (or in a
/// call hidden from them), and hears exactly that from this gate when the
/// target is in a call they can see: the same check, raised by the same
/// `throw_if_lacking_channel_permission`, so the same status and the same
/// error body.
///
/// Spelled out rather than sharing a body with the destination gate: the
/// contract tests in `revolt-database` read each gate's body and each gate's
/// call site on their own, and the two ends are free to diverge later without
/// one of them silently inheriting the other's rule. Their order already
/// differs: the mover names the destination, so what that gate answers is
/// only the mover's own standing on a channel they chose, and its order
/// tells them nothing about the target.
async fn assert_mover_may_move_out_of(db: &Database, user: &User, source: &Channel) -> Result<()> {
    let mut query = DatabasePermissionQuery::new(db, user).channel(source);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    Ok(())
}

/// Whether the acting user can SEE the target's source channel, with that
/// channel's own overrides applied (operator ruling 2026-09-28, merge slice
/// FXA-1). A source they cannot see is, for them, no call at all: the route
/// then answers exactly what it answers for a target in no call, so the
/// answer never says whether the target sits in a call hidden from the
/// mover. See `assert_mover_may_move_out_of`, which is asked only about a
/// source this answers `true` for.
///
/// The server owner and platform staff get `GrantAllSafe` from the calculus
/// and see every channel, so this never hides a call from them.
async fn mover_can_see_source(db: &Database, user: &User, source: &Channel) -> bool {
    let mut query = DatabasePermissionQuery::new(db, user).channel(source);
    calculate_channel_permissions(&mut query)
        .await
        .has_channel_permission(ChannelPermission::ViewChannel)
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
    // session. Only a self-move reads it (see `policy` below).
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
    //
    // Platform staff resolve no member rank (`i64::MIN`), which now ties with
    // the owner's, so they are exempt here to keep the reach they already had.
    if member.id.user != user.id
        && !user.privileged
        && member.get_ranking(query.server_ref().as_ref().unwrap()) <= our_ranking
    {
        return Err(create_error!(NotElevated));
    }

    // The channel the target is in, read ONCE, and the one the source-side
    // gate below decides about. Every later use in the move path is this
    // value, never a fresh read (AFK Stage 6 F-A3): a fresh read could name a
    // channel the target switched to after the gate ran, one the mover was
    // never checked against. `None` outside the voice shapes, when the
    // target is in no call in this server, and when somebody else acts on a
    // target sitting in a call they cannot see (merge slice FXA-1).
    let voice_shape =
        data.voice_channel.is_some() || data.remove.contains(&FieldsMember::VoiceChannel);
    let source_id = if voice_shape {
        if !voice_client.is_enabled() {
            return Err(create_error!(LiveKitUnavailable));
        };

        // The MOVER's side of the SOURCE — the call the target is being taken
        // out of — evaluated with that channel's own overrides applied. See
        // `assert_mover_may_move_out_of`. `MoveMembers` is decided per
        // channel (ruling D0-3, merge slice RT-4): on the source here, on
        // the destination below. There is no unconditional server-scoped
        // `MoveMembers` check any more; it read no channel override, so it
        // refused a moderator whose `MoveMembers` comes from overrides on
        // the two channels alone.
        //
        // Sits in this block, not in the move branch below, because the
        // disconnect shape reaches into the same channel the same way and is
        // decided here too — its own eviction runs after the member document
        // has already been written.
        //
        // A call the mover cannot SEE is, for them, no call at all (operator
        // ruling 2026-09-28, merge slice FXA-1). The mover does not name the
        // source; it is wherever the target happens to be, so whatever is
        // decided about it is an answer about the target. Gated like a
        // visible call, a hidden one answered 403 where a target in no call
        // gets a 200 no-op (disconnect) or `NotConnected` (move) from a mover
        // holding `MoveMembers` server-wide, and so told them who sits in a
        // channel they cannot even see. Treated as no call, every later step
        // sees `None`: the server-scoped fallback below decides, a
        // disconnect is the same 200 no-op (nothing evicted, no record
        // dropped, the target stays connected) and a move answers exactly
        // what a move of a target in no call answers, byte for byte, with
        // or without `MoveMembers` anywhere. Asked of the channel already
        // resolved here, so the pointer is still read once (F-A3). Never for
        // a self-edit: nobody is hidden from their own call.
        //
        // No source means the target is in no call in this server (or in
        // one hidden from the mover). There is no channel to scope
        // `MoveMembers` to, so somebody else's move or disconnect needs it
        // server-wide instead. Without that fallback a disconnect by
        // somebody with no `MoveMembers` anywhere answers 200 for a target in
        // no call and a refusal for one in a call, which tells them who is
        // in voice. The source gate asks `MoveMembers` before `ViewChannel`
        // for the same reason (merge slice M2C-1), so such a mover hears the
        // fallback's exact refusal whether the target is in no call, in a
        // call hidden from them (the fallback itself), or in one they can see
        // (the gate). The move branch below still answers `NotConnected` in
        // its own place. An unresolvable source channel propagates rather
        // than being waved through: a gate whose subject cannot be read
        // refuses.
        let source_id = get_user_voice_channel_in_server(&target_user.id, &server.id).await?;
        let source_id = match source_id {
            Some(source_id) => {
                let source = Reference::from_unchecked(&source_id).as_channel(db).await?;

                if member.id.user != user.id && !mover_can_see_source(db, &user, &source).await {
                    None
                } else {
                    // Self-move exemption, same as the destination gate:
                    // leaving a call you are in is not exercising
                    // `MoveMembers` over anybody.
                    if member.id.user != user.id {
                        assert_mover_may_move_out_of(db, &user, &source).await?;
                    }

                    Some(source_id)
                }
            }
            None => None,
        };

        if source_id.is_none() && member.id.user != user.id {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;
        }

        source_id
    } else {
        None
    };

    // The session the request came in on, when it is the caller's own. `None`
    // for a bot, which has no session.
    let request_session = session
        .as_ref()
        .filter(|session| session.user_id == user.id)
        .map(|session| session.id.as_str());

    // THE move policy (merge slice SEC3-1), bound once and decided by WHO IS
    // MOVED and nothing else: moving yourself is a `SelfMove`, whatever
    // permissions you hold, and moving anybody else is a `Moderator` move.
    // It decides the target's admission (a self-move needs Connect and obeys
    // `max_users`; a moderator's move does neither, rulings D0-1 / D0-2) and,
    // for a self-move, that the request comes from the session that owns
    // the participant. Deciding it from permissions instead would let a
    // stolen session of a member who holds `MoveMembers` label its own
    // self-move `Moderator` and skip the owner check, Connect and the user
    // limit. The SAME binding goes to the pre-flight and to the move, so the
    // two can never admit under different rules.
    let policy = if member.id.user == user.id {
        MovePolicy::SelfMove { request_session }
    } else {
        MovePolicy::Moderator
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
        // overrides applied: `MoveMembers`, `ViewChannel` and `Connect`
        // there (see `assert_mover_may_move_into`).
        //
        // Skipped for a self-move, consistently with the source-side gate:
        // moving yourself is not exercising `MoveMembers` over anybody, and
        // the target-side gates below already answer for you.
        //
        // First of the pre-flight gates on purpose, and now genuinely first:
        // the ranking check and the source-side gate are both answered above,
        // so an unauthorized mover is refused before the destination is
        // inspected at all and a refusal never reports whether the channel is
        // full or who is in it.
        if member.id.user != user.id {
            assert_mover_may_move_into(db, &user, &channel).await?;
        }

        // A bot is never moved (ruling 09-27, merge slice P2A-16): it has no
        // session, so nobody could be told about the move, and a moderator's
        // move would silently become a disconnect. Refused with an error
        // instead, before anything is written; the moderator can still
        // disconnect it (`remove: ["VoiceChannel"]` never reaches this
        // branch). A bot moving itself is refused the same way.
        if target_user.bot.is_some() {
            return Err(create_error!(IsBot));
        }

        // Every admission refusal the move itself can raise, under the SAME
        // `policy` the move runs with: the destination really is a voice
        // channel in this server, the target is a member who can VIEW it, and
        // the call-admission caps (D12 video cap + T-20 MLS SFU coupling)
        // admit them. A self-move also needs the target's Connect there and
        // obeys `max_users` (with the join front door's `ManageChannel`
        // exemption); a moderator's move needs neither here (rulings D0-1 /
        // D0-2). All of it is side-effect free and all of it runs BEFORE any
        // member mutation below, so a refusal leaves the member untouched —
        // the property the caps check was originally placed here for, and
        // the property the mover gates above share.
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
        // not a substitute for it. What only the move can see (the SFU's
        // listing, whether the owner can be handed a token) it answers
        // itself, after the write.
        assert_voice_move_admissible(db, &target_user, &channel, policy).await?;

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

        // The session that owns the target's participant in the gated
        // source (`join_call` recorded it), read ONCE, for EVERY move (merge
        // slice RT-2). The move is announced to that session alone, and
        // handed to the move as `expected_session`; the self-move check just
        // below decides on this same value. It is never taken from the
        // request: `None` would turn a moderator's move into a disconnect,
        // and the caller's own session would be planned as the owner of a
        // participant it may not own.
        let expected_session = get_voice_participant_session(&source_id, &target_user.id).await?;

        // A self-move goes ahead only from that owning session (invariant B4,
        // merge slice SEC3-1): any other session of the same user would
        // steer the owning one, which obeys the move event, into a channel
        // it never chose (a stolen web session moving the victim's desktop).
        // With no session recorded the owner is unknown and the move is
        // refused too. The move checks the same thing itself; asked here as
        // well, it refuses BEFORE the member document is written, so a
        // refused self-move applies nothing else from the same PATCH. A
        // "move" into the call the user is already in (a sibling session's
        // request, say) changes nothing and is not checked: the move answers
        // it as the `AlreadyPresent` no-op.
        if let MovePolicy::SelfMove { request_session } = policy {
            if source_id != channel.id()
                && !self_move_from_owning_session(expected_session.as_deref(), request_session)
            {
                return Err(create_error!(NotAuthenticated));
            }
        }

        Some((channel, source_id, expected_session))
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

    if let Some((new_voice_channel, source_id, expected_session)) = new_voice_channel {
        // The move itself is server-authoritative and lives in the database
        // layer, because the AFK sweep needs the same behavior with no
        // acting user and no Rocket request to hang it off. Everything that
        // is route policy — LiveKit being enabled, `MoveMembers`, ranking,
        // bots, the self-move owner — has already been decided above;
        // everything that is about the move being possible and safe,
        // including who is told about it and with what token, is decided in
        // there.
        //
        // EXPECTING the source the mover was gated on (AFK Stage 6 F-A3; the
        // expectation is a required argument since the S-3 cleanup).
        // Re-deriving the source from the pointer would pull a target who
        // switched channels after the gate out of a channel the mover was
        // never authorized over. With the expectation that switch answers
        // `NotConnected` before anything is listed, written or minted. The
        // owning session read above, and the one `policy`, go with it.
        //
        // - `Moved`: done. `AlreadyPresent`: there was nothing to do, the
        //   target is where they were asked to be, so a 200 is the truth.
        //   `Disconnected`: a moderator's move of a participant no session
        //   is recorded as owning (a join from before the record existed);
        //   nobody could be told where to go, so the move was done as the
        //   disconnect it amounts to, which is also a 200 (a self-move never
        //   gets here without an owner, it is refused above).
        // - `NotConnected`: NO move happened. The target left, or switched
        //   away from the gated source, after the precondition above, or
        //   another session took the participant over while the move ran.
        //   Answered as the `NotConnected` error the precondition itself
        //   gives (AFK Stage 6 FU-C), never as a success.
        // - `TargetCannotJoin`: refused before the move wrote anything. The
        //   owning session could only be told without a token, and the
        //   `join_call` its client would then make refuses the target (no
        //   Connect on the destination, or a full one), so carrying it out
        //   would evict them into no call. Answered as `CannotJoinCall`,
        //   `join_call`'s own refusal of a full channel.
        //
        // The member document above is already written by this point: any
        // nickname, pronouns or avatar sent in the same PATCH stays applied,
        // exactly as it does for every other error the move can raise from
        // here (`UnknownNode`, a caps refusal). The fields that change the
        // permissions a move is decided under cannot be in this PATCH at all
        // (refused above).
        //
        // Matched exhaustively, so a new outcome has to be classified here.
        match move_user_to_voice_channel_expecting(
            db,
            voice_client,
            &target_user,
            &new_voice_channel,
            &source_id,
            expected_session.as_deref(),
            policy,
        )
        .await?
        {
            VoiceMoveOutcome::Moved { .. }
            | VoiceMoveOutcome::AlreadyPresent
            | VoiceMoveOutcome::Disconnected => {}
            VoiceMoveOutcome::NotConnected => return Err(create_error!(NotConnected)),
            VoiceMoveOutcome::TargetCannotJoin => return Err(create_error!(CannotJoinCall)),
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
        // or somebody else asked while the target sat in a call hidden from
        // them (merge slice FXA-1), and clearing `VoiceChannel` is a no-op,
        // as it always has been (the client's call-moderation policy relies
        // on that). Nothing is evicted and no record is dropped.
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

            // 3. The target's session record for the gated source, dropped
            //    BEFORE the release and the eviction (media-e2ee S6M-2 /
            //    SEC6-1). A move already in flight out of this channel
            //    compares that record right before it announces the move.
            //    Left in place, it would still name the session this
            //    disconnect evicts, the compare would pass, and the evicted
            //    owner would be handed a token for the destination (the F1
            //    shape). Dropped first, the compare fails and the move is
            //    refused. This is a kick, not a leave: the reason a leave
            //    keeps its record (livekit's full reconnect never calls
            //    `join_call`, so the rejoin would find none) does not apply,
            //    exactly as for `join_call`'s own kick loop. It covers a
            //    self-disconnect from a sibling session too, which is not
            //    owner-gated: that sibling evicts the owning session all the
            //    same.
            //
            //    Only a drop that lands BEFORE the move's compare reads the
            //    record is seen (media-e2ee S6R-2): one that lands after it,
            //    in the move's window from that compare to its publish (Redis
            //    writes only), is not, and that move is still announced to
            //    the session evicted here. That is the accepted residual
            //    (merge slice SEC2-7's class).
            //
            //    A failed drop returns the error with nothing released,
            //    evicted or torn down: the disconnect is refused with the
            //    record intact, never carried out with a record a move could
            //    still hand a token to. The reverse, a drop followed by a
            //    failed eviction below, leaves the target connected with no
            //    record: the safe direction, since a move then finds no owner
            //    and is refused (a self-move) or done as the disconnect it
            //    amounts to (a moderator's), and nobody is handed a token.
            drop_voice_participant_session(channel, &target_user.id).await?;

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
                // 4. `returned ∪ (recorded − returned)`: every sid the
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
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            delete_voice_participant_identity, get_user_moved_to_voice,
            get_user_voice_channel_in_server, get_voice_channel_members, get_voice_state,
            is_in_voice_channel, record_voice_connection, recorded_voice_connections,
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
        let (_b, session_b, user_b) = harness.new_user().await; // target being moved
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let source = voice_channel(&harness, &server, "Source").await;
        let dest_full = voice_channel(&harness, &server, "DestFull").await;
        let dest_member = voice_channel(&harness, &server, "DestMember").await;

        // Target is connected in the source channel (the move precondition),
        // from a session recorded as owning the participant (so the move past
        // the caps is a move, not the disconnect of a participant nobody
        // owns), and the source has a node so the exemption path can proceed
        // past the caps into the (unreachable-in-test) LiveKit machinery.
        let source_uvc = UserVoiceChannel::from_channel(&source);
        create_voice_state(&source_uvc, &user_b.id, Timestamp::now_utc())
            .await
            .expect("voice state");
        revolt_database::voice::set_voice_participant_session(
            source.id(),
            &user_b.id,
            &session_b.id,
            None,
        )
        .await
        .expect("session record");
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
    // A move that clears every check resolves the LiveKit URL of the node the
    // destination room would open on (the source's). The fixture pins that to
    // `ABSENT_NODE`, so the move fails fast with `UnknownNode`: that error is
    // the observable for "got past every permission and destination check",
    // and is asserted exactly rather than as "not a 403". It is answered
    // before the SFU listing and before any write, for every move that gets
    // that far, owner recorded or not, so it is never mistaken for a
    // move that became a disconnect (`Disconnected`, a 200). What the move
    // does past that point (the carry, the delivery, the eviction) is driven
    // on the database crate's stub SFU, which is not reachable from here.

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
        /// The session `target_token` belongs to, recorded as the owner of
        /// the target's participant in `source`.
        target_session: String,
        source: Channel,
        dest: Channel,
        source_uvc: UserVoiceChannel,
    }

    impl MoveFixture {
        async fn cleanup(&self) {
            delete_channel_voice_state(&self.source_uvc, &[self.target.id.clone()])
                .await
                .expect("cleanup source");
            // A move that got as far as the carry-over or the node pin left
            // those on the destination.
            delete_channel_voice_state(&UserVoiceChannel::from_channel(&self.dest), &[])
                .await
                .expect("cleanup dest");
        }
    }

    /// Drop the target's session record in `channel`, as for a participant
    /// that joined before the record existed. No route does this.
    async fn forget_session_record(channel: &Channel, user_id: &str) {
        use redis_kiss::AsyncCommands;
        use revolt_database::voice::voice_session_key;

        let _: () = redis_kiss::get_connection()
            .await
            .expect("redis")
            .hdel(voice_session_key(channel.id()), user_id)
            .await
            .expect("drop record");
    }

    /// The session recorded as the owner of `user_id`'s participant in
    /// `channel`.
    async fn recorded_session(channel: &Channel, user_id: &str) -> Option<String> {
        revolt_database::voice::get_voice_participant_session(channel.id(), user_id)
            .await
            .expect("session record read")
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
    /// in `source` from the session `target_token` belongs to, which
    /// `join_call` records as the owner of their participant there.
    async fn move_fixture(server_move_members: bool) -> MoveFixture {
        use revolt_database::voice::set_voice_participant_session;

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
        // Joined bare (no identity mapping names a device), so recorded as a
        // bare seat.
        set_voice_participant_session(source.id(), &target.id, &session_t.id, None)
            .await
            .expect("session record");

        MoveFixture {
            harness,
            server,
            moderator,
            mod_token: session_m.token,
            mod_role,
            target,
            target_token: session_t.token,
            target_session: session_t.id,
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
    fn move_needs_the_mover_to_connect_to_the_destination() {
        crate::util::test::rt().block_on(move_needs_the_mover_to_connect_to_the_destination_case())
    }

    /// Ruling 09-27: a moderator may only pull somebody into a channel they
    /// could join themselves. The moderator's role is denied Connect on the
    /// destination (and keeps MoveMembers and ViewChannel there); the
    /// target, on the default role, is untouched, so the refusal can only be
    /// the mover-side gate. The same move without the override reaches the
    /// absent node.
    async fn move_needs_the_mover_to_connect_to_the_destination_case() {
        let f = move_fixture(true).await;

        let response = move_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        channel_override(
            &f.harness,
            &f.dest,
            &f.mod_role,
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
        assert_missing_permission(response, ChannelPermission::Connect).await;
        assert!(
            get_voice_state(&f.source_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused move must leave the target connected"
        );

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
    fn vm_move_into_a_text_channel_is_refused() {
        crate::util::test::rt().block_on(vm_move_into_a_text_channel_is_refused_case())
    }

    async fn vm_move_into_a_text_channel_is_refused_case() {
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
    fn move_into_the_current_channel_is_a_no_op() {
        crate::util::test::rt().block_on(move_into_the_current_channel_is_a_no_op_case())
    }

    /// User ruling 2026-09-26: a move into the channel the target is already
    /// in succeeds and does nothing. The fixture's source node is absent, so
    /// any kick, room or token would have failed `UnknownNode`: a 200 means
    /// none was attempted.
    ///
    /// A sibling session of the target asking the same is a no-op too
    /// (merge slice m1_rt LOW): the self-move owner check is skipped when the
    /// source is the destination, because nothing moves and nobody is told.
    async fn move_into_the_current_channel_is_a_no_op_case() {
        let f = move_fixture(true).await;
        let sibling = f
            .harness
            .db
            .fetch_account(&f.target.id)
            .await
            .expect("account")
            .create_session(&f.harness.db, String::new())
            .await
            .expect("sibling session");

        for (token, who) in [
            (&f.mod_token, "a moderator"),
            (&f.target_token, "the target"),
            (&sibling.token, "a sibling session of the target"),
        ] {
            let response =
                move_member(&f.harness, token, &f.server.id, &f.target.id, f.source.id()).await;
            assert_eq!(
                response.status(),
                Status::Ok,
                "{who}: a move into the current channel is a no-op, got {:?}",
                response.into_string().await
            );

            assert!(
                get_voice_state(&f.source_uvc, &f.target.id)
                    .await
                    .expect("voice state read")
                    .is_some(),
                "{}: the target is still connected in the source",
                who
            );
            // No `moved_to` label (merge slice M2A-3; voice-move's
            // `moved_from` marker is not ported): the no-op wrote nothing a
            // later Join of the target could be relabelled by.
            assert_eq!(
                get_user_moved_to_voice(f.source.id(), &f.target.id)
                    .await
                    .expect("marker read"),
                None,
                "{who}: the no-op must not write a move label"
            );
            assert_eq!(
                recorded_session(&f.source, &f.target.id).await,
                Some(f.target_session.clone()),
                "{who}: the session record is untouched"
            );
        }

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
    /// its ManageChannel exemption; a moderator move is not held to it
    /// (ruling D0-2).
    ///
    /// The self-move's refusal comes from the route's pre-flight, under the
    /// same `policy` the move would run with, so it lands BEFORE the member
    /// document is written: pronouns sent with it are not applied. A
    /// pre-flight run under another policy than the move's would let the
    /// write through and leave the refusal to the move (control
    /// POLICY-SPLIT).
    async fn self_move_into_a_full_channel_is_refused_case() {
        let f = move_fixture(true).await;
        let full = limited_voice_channel(&f.harness, &f.server, "Full", Some(1)).await;
        let full_uvc = UserVoiceChannel::from_channel(&full);
        let occupant = "0SYNTHFULLCHANNELUSER00000".to_string();
        create_voice_state(&full_uvc, &occupant, Timestamp::now_utc())
            .await
            .expect("occupant");

        let response = edit_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            serde_json::json!({ "voice_channel": full.id(), "pronouns": "they/them" }),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest);
        assert!(
            matches!(error, revolt_result::ErrorType::CannotJoinCall),
            "a self-move into a full channel must be refused like a join, got {:?}",
            error
        );
        assert_eq!(
            f.harness
                .db
                .fetch_member(&f.server.id, &f.target.id)
                .await
                .expect("member read")
                .pronouns,
            None,
            "the refused self-move must leave the member document untouched"
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

    #[test]
    fn a_disconnect_without_move_members_does_not_say_where_the_target_is() {
        crate::util::test::rt().block_on(a_mover_without_move_members_learns_nothing_case(false))
    }

    #[test]
    fn a_move_without_move_members_does_not_say_where_the_target_is() {
        crate::util::test::rt().block_on(a_mover_without_move_members_learns_nothing_case(true))
    }

    /// The status and the raw body of the answer `f`'s moderator gets for
    /// `body` on `f`'s target.
    async fn answer_to_the_moderator(
        f: &MoveFixture,
        body: &serde_json::Value,
    ) -> (Status, String) {
        let response = edit_member(
            &f.harness,
            &f.mod_token,
            &f.server.id,
            &f.target.id,
            body.clone(),
        )
        .await;
        let status = response.status();
        (status, response.into_string().await.expect("a body"))
    }

    /// Whether `f`'s moderator holds `permission`, as the permission calculus
    /// the route runs answers it: on `channel` with its overrides applied
    /// (re-read, the fixture's copy predates them), or server-wide for
    /// `None`. Merge slice FXA-2: the tests that rest on who can see what
    /// assert their own setup through it.
    async fn mover_holds(
        f: &MoveFixture,
        channel: Option<&Channel>,
        permission: ChannelPermission,
    ) -> bool {
        use revolt_database::util::permissions::DatabasePermissionQuery;
        use revolt_permissions::{calculate_channel_permissions, calculate_server_permissions};

        match channel {
            Some(channel) => {
                let channel = f
                    .harness
                    .db
                    .fetch_channel(channel.id())
                    .await
                    .expect("channel read");
                let mut query =
                    DatabasePermissionQuery::new(&f.harness.db, &f.moderator).channel(&channel);
                calculate_channel_permissions(&mut query)
                    .await
                    .has_channel_permission(permission)
            }
            None => {
                let server = f
                    .harness
                    .db
                    .fetch_server(&f.server.id)
                    .await
                    .expect("server read");
                let mut query =
                    DatabasePermissionQuery::new(&f.harness.db, &f.moderator).server(&server);
                calculate_server_permissions(&mut query)
                    .await
                    .has_channel_permission(permission)
            }
        }
    }

    /// The channel the per-server pointer of `f`'s target names.
    async fn target_pointer(f: &MoveFixture) -> Option<String> {
        get_user_voice_channel_in_server(&f.target.id, &f.server.id)
            .await
            .expect("pointer read")
    }

    /// Merge slice M2C-1: no presence oracle. The moderator outranks the
    /// target but holds `MoveMembers` nowhere, and asks to disconnect (or
    /// move) them while they are in a voice channel the moderator can see,
    /// in one hidden from the moderator, and in no call at all. All three
    /// are refused, and the three refusals must be the SAME, status and
    /// whole error body alike (its `location` included), or the refusal
    /// itself says where the target is. The source gate used to ask
    /// `ViewChannel` first, so the hidden call alone answered
    /// `MissingPermission` for `ViewChannel`. Since the FXA-1 ruling the
    /// hidden call is no call and the fallback answers it; the visible one
    /// is still answered by the source gate.
    ///
    /// Merge slice FXA-2: the setup is asserted through the calculus, not
    /// assumed: the moderator cannot see the hidden channel, can see the
    /// source, and holds `MoveMembers` nowhere (server-wide, source, hidden,
    /// destination).
    ///
    /// Two tests, one per shape, each sending three requests from the one
    /// moderator: the `servers` ratelimit bucket allows five per window
    /// (see `moving_and_editing_voice_permissions_case`).
    async fn a_mover_without_move_members_learns_nothing_case(move_shape: bool) {
        let f = move_fixture(false).await;
        let hidden = voice_channel(&f.harness, &f.server, "Hidden").await;
        channel_override(
            &f.harness,
            &hidden,
            &f.mod_role,
            0,
            ChannelPermission::ViewChannel as u64,
        )
        .await;
        let hidden_uvc = UserVoiceChannel::from_channel(&hidden);

        assert!(
            !mover_holds(&f, Some(&hidden), ChannelPermission::ViewChannel).await,
            "setup: the moderator must not see the hidden channel"
        );
        assert!(
            mover_holds(&f, Some(&f.source), ChannelPermission::ViewChannel).await,
            "setup: the moderator must see the source"
        );
        for (channel, place) in [
            (None, "server-wide"),
            (Some(&f.source), "on the source"),
            (Some(&hidden), "on the hidden channel"),
            (Some(&f.dest), "on the destination"),
        ] {
            assert!(
                !mover_holds(&f, channel, ChannelPermission::MoveMembers).await,
                "setup: the moderator must hold MoveMembers nowhere, holds it {}",
                place
            );
        }
        let body = if move_shape {
            serde_json::json!({ "voice_channel": f.dest.id() })
        } else {
            serde_json::json!({ "remove": ["VoiceChannel"] })
        };

        // In a call the moderator can see (the fixture's source).
        let in_visible = answer_to_the_moderator(&f, &body).await;

        // In a call hidden from the moderator.
        delete_channel_voice_state(&f.source_uvc, &[f.target.id.clone()])
            .await
            .expect("leave the source");
        create_voice_state(&hidden_uvc, &f.target.id, Timestamp::now_utc())
            .await
            .expect("join the hidden call");
        assert_eq!(
            get_user_voice_channel_in_server(&f.target.id, &f.server.id)
                .await
                .expect("pointer read")
                .as_deref(),
            Some(hidden.id()),
            "the target must sit in the hidden call"
        );
        let in_hidden = answer_to_the_moderator(&f, &body).await;
        assert!(
            get_voice_state(&hidden_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refusal must leave the target in the hidden call"
        );

        // In no call at all (the server-scoped fallback answers).
        delete_channel_voice_state(&hidden_uvc, &[f.target.id.clone()])
            .await
            .expect("leave the hidden call");
        assert_eq!(
            get_user_voice_channel_in_server(&f.target.id, &f.server.id)
                .await
                .expect("pointer read"),
            None,
            "the target must be in no call"
        );
        let in_none = answer_to_the_moderator(&f, &body).await;

        for ((status, body), place) in [
            (&in_visible, "a visible call"),
            (&in_hidden, "a hidden call"),
            (&in_none, "no call"),
        ] {
            assert_eq!(*status, Status::Forbidden, "target in {place}: {body}");
            let error: revolt_result::Error = serde_json::from_str(body).expect("an error body");
            assert!(
                matches!(
                    &error.error_type,
                    revolt_result::ErrorType::MissingPermission { permission }
                        if *permission == ChannelPermission::MoveMembers.to_string()
                ),
                "target in {}: expected MissingPermission MoveMembers, got {}",
                place,
                body
            );
        }
        assert_eq!(
            in_hidden, in_none,
            "a target in a call hidden from the mover must be told apart from \
             one in no call by nothing at all"
        );
        assert_eq!(
            in_visible, in_none,
            "a target in a visible call must be told apart from one in no \
             call by nothing at all"
        );

        f.cleanup().await;
    }

    #[test]
    fn a_mover_with_server_move_members_cannot_find_a_hidden_call_by_disconnecting() {
        crate::util::test::rt().block_on(a_hidden_call_is_no_call_case(false))
    }

    #[test]
    fn a_mover_with_server_move_members_cannot_find_a_hidden_call_by_moving() {
        crate::util::test::rt().block_on(a_hidden_call_is_no_call_case(true))
    }

    /// Operator ruling 2026-09-28 (merge slice FXA-1): a call the mover
    /// cannot see is, for them, no call. The moderator outranks the target
    /// and holds `MoveMembers` SERVER-WIDE, so the no-source fallback lets
    /// them through, and asks to disconnect (or move) the target while the
    /// target sits in a voice channel hidden from them, then while the
    /// target is in no call. The two answers must be the SAME, status and
    /// raw body alike: a 200 no-op for the disconnect, `NotConnected` for
    /// the move. Before the ruling the hidden call answered 403
    /// `MissingPermission` from the source gate, which told the moderator
    /// who sits in a channel they cannot see (control HIDDEN-GATED).
    ///
    /// And nothing happens to the target in the hidden call: still
    /// connected, the pointer still names it, the session record that owns
    /// the participant still there (control HIDDEN-EVICTS: the hidden
    /// source kept, so the disconnect tears the target down and drops the
    /// record, and still answers the same 200). The target in no call keeps
    /// a record left behind in the source: a no-call disconnect drops
    /// nothing either.
    ///
    /// Merge slice FXA-2: the setup is asserted through the calculus: the
    /// moderator cannot see the hidden channel, can see the source, and
    /// holds `MoveMembers` server-wide. Two requests per test (the `servers`
    /// ratelimit bucket, see `a_mover_without_move_members_learns_nothing_case`).
    async fn a_hidden_call_is_no_call_case(move_shape: bool) {
        use revolt_database::voice::set_voice_participant_session;

        let f = move_fixture(true).await;
        let hidden = voice_channel(&f.harness, &f.server, "Hidden").await;
        channel_override(
            &f.harness,
            &hidden,
            &f.mod_role,
            0,
            ChannelPermission::ViewChannel as u64,
        )
        .await;
        let hidden_uvc = UserVoiceChannel::from_channel(&hidden);

        assert!(
            !mover_holds(&f, Some(&hidden), ChannelPermission::ViewChannel).await,
            "setup: the moderator must not see the hidden channel"
        );
        assert!(
            mover_holds(&f, Some(&f.source), ChannelPermission::ViewChannel).await,
            "setup: the moderator must see the source"
        );
        assert!(
            mover_holds(&f, None, ChannelPermission::MoveMembers).await,
            "setup: the moderator must hold MoveMembers server-wide"
        );

        let body = if move_shape {
            serde_json::json!({ "voice_channel": f.dest.id() })
        } else {
            serde_json::json!({ "remove": ["VoiceChannel"] })
        };
        // In a call hidden from the moderator, owned by the target's session.
        delete_channel_voice_state(&f.source_uvc, &[f.target.id.clone()])
            .await
            .expect("leave the source");
        create_voice_state(&hidden_uvc, &f.target.id, Timestamp::now_utc())
            .await
            .expect("join the hidden call");
        set_voice_participant_session(hidden.id(), &f.target.id, &f.target_session, None)
            .await
            .expect("session record");
        assert_eq!(
            target_pointer(&f).await.as_deref(),
            Some(hidden.id()),
            "setup: the target must sit in the hidden call"
        );
        let in_hidden = answer_to_the_moderator(&f, &body).await;

        assert!(
            get_voice_state(&hidden_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the target in the hidden call must still be connected: {:?}",
            in_hidden
        );
        assert_eq!(
            target_pointer(&f).await.as_deref(),
            Some(hidden.id()),
            "the pointer must still name the hidden call"
        );
        assert_eq!(
            recorded_session(&hidden, &f.target.id).await,
            Some(f.target_session.clone()),
            "the hidden call's session record must be untouched"
        );

        // In no call at all, with a record left behind in the source.
        delete_channel_voice_state(&hidden_uvc, &[f.target.id.clone()])
            .await
            .expect("leave the hidden call");
        set_voice_participant_session(f.source.id(), &f.target.id, &f.target_session, None)
            .await
            .expect("left-behind record");
        assert_eq!(
            target_pointer(&f).await,
            None,
            "setup: the target must be in no call"
        );
        let in_none = answer_to_the_moderator(&f, &body).await;

        assert_eq!(
            recorded_session(&f.source, &f.target.id).await,
            Some(f.target_session.clone()),
            "a disconnect of a target in no call drops no record"
        );
        if move_shape {
            assert_eq!(in_none.0, Status::BadRequest, "{}", in_none.1);
            let error: revolt_result::Error =
                serde_json::from_str(&in_none.1).expect("an error body");
            assert!(
                matches!(error.error_type, revolt_result::ErrorType::NotConnected),
                "a move of a target in no call is NotConnected, got {}",
                in_none.1
            );
        } else {
            assert_eq!(
                in_none.0,
                Status::Ok,
                "a disconnect of a target in no call is a no-op: {}",
                in_none.1
            );
        }
        assert_eq!(
            in_hidden, in_none,
            "a target in a call hidden from the mover must be told apart from \
             one in no call by nothing at all"
        );

        f.cleanup().await;
    }

    #[test]
    fn a_disconnect_drops_the_targets_session_record_first() {
        crate::util::test::rt().block_on(a_disconnect_drops_the_targets_session_record_first_case())
    }

    /// Media-e2ee S6M-2 / SEC6-1: a disconnect drops the target's session
    /// record for the gated source BEFORE it evicts. Left in place, a move
    /// already in flight out of the channel would pass its compare of that
    /// record and hand the evicted owner a token. A moderator's disconnect
    /// and a self-disconnect from a sibling session of the target (not the
    /// owning one, and not owner-gated) both drop it.
    ///
    /// The source's node is `ABSENT_NODE`, so the eviction fails with
    /// `UnknownNode` after the drop: the record is gone all the same, and the
    /// failed eviction tears nothing down, so the target is left connected
    /// with no record, the safe direction (nobody can be handed a token for
    /// that seat). With no node at all there is nothing to evict and the
    /// disconnect succeeds; the record goes then too. Controls NODROP-DISC
    /// (the drop deleted) and DROPLATE-DISC (the drop moved after the
    /// eviction, which fails first) turn the first two legs red.
    async fn a_disconnect_drops_the_targets_session_record_first_case() {
        use revolt_database::voice::set_voice_participant_session;

        let f = move_fixture(true).await;
        let sibling = f
            .harness
            .db
            .fetch_account(&f.target.id)
            .await
            .expect("account")
            .create_session(&f.harness.db, String::new())
            .await
            .expect("sibling session");
        assert_ne!(sibling.id, f.target_session, "setup: a second session");

        for (token, who) in [
            (&f.mod_token, "a moderator"),
            (&sibling.token, "a sibling session of the target"),
        ] {
            set_voice_participant_session(f.source.id(), &f.target.id, &f.target_session, None)
                .await
                .expect("session record");
            assert_eq!(
                recorded_session(&f.source, &f.target.id).await,
                Some(f.target_session.clone()),
                "{who}: setup: the owning session is recorded"
            );

            let response = disconnect_member(&f.harness, token, &f.server.id, &f.target.id).await;
            let (status, error) = error_of(response).await;
            assert!(
                matches!(error, revolt_result::ErrorType::UnknownNode),
                "{}: the eviction must be what fails, at the absent node, got {} {:?}",
                who,
                status,
                error
            );
            assert_eq!(
                recorded_session(&f.source, &f.target.id).await,
                None,
                "{who}: the record must be dropped before the eviction, even one that fails"
            );
            assert!(
                get_voice_state(&f.source_uvc, &f.target.id)
                    .await
                    .expect("voice state read")
                    .is_some(),
                "{}: the failed eviction tears nothing down",
                who
            );
        }

        set_voice_participant_session(f.source.id(), &f.target.id, &f.target_session, None)
            .await
            .expect("session record");
        delete_channel_node(f.source.id()).await.expect("drop node");
        let response =
            disconnect_member(&f.harness, &f.mod_token, &f.server.id, &f.target.id).await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "with no node there is nothing to evict: {:?}",
            response.into_string().await
        );
        assert_eq!(
            recorded_session(&f.source, &f.target.id).await,
            None,
            "the record is dropped when the disconnect succeeds too"
        );

        f.cleanup().await;
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

    /// The shipping source of `fn {name}` in this file, comments stripped
    /// (`crate::util::test::without_comments`): from its signature to the
    /// first closing brace in column 0.
    fn shipping_fn(name: &str) -> String {
        let source = include_str!("member_edit.rs");
        let shipping = crate::util::test::without_comments(
            &source[..source.find("#[cfg(test)]").expect("test module")],
        );
        let start = shipping
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| panic!("`{}` left member_edit.rs", name));
        let end = start
            + shipping[start..]
                .find("\n\u{7d}\n")
                .expect("the end of the fn");
        shipping[start..end].to_string()
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
    fn a_web_session_cannot_self_move_a_device_bound_participant() {
        crate::util::test::rt()
            .block_on(a_web_session_cannot_self_move_a_device_bound_participant_case())
    }

    /// The target is in the call as `target:device`, joined from the session
    /// bound to that device. Their web session moving them would steer the
    /// bound session (and, handed the device's token, act as that device),
    /// so it is refused before anything is written: it does not own the
    /// participant. The bound session and a moderator are unaffected. Once
    /// the participant is bare, the web session is STILL refused (lane 6a2).
    ///
    /// Merge slice RT-5: voice-move's route also checked the identity
    /// mapping's device against the web session (M2), which answered the
    /// first request `FailedValidation`. That check is not ported; the owner
    /// check answers it, `NotAuthenticated`, and the device binding of any
    /// token is the move's own (`move_event_delivery` in the database crate).
    async fn a_web_session_cannot_self_move_a_device_bound_participant_case() {
        use revolt_database::voice::set_voice_participant_session;

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
        // A device-qualified join comes from the bound session, so that is
        // the session `join_call` recorded, seated as the device.
        set_voice_participant_session(f.source.id(), &f.target.id, &bound.id, Some(&device))
            .await
            .expect("session record");

        // No identity row yet: the web session does not own the participant.
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
            "a session that does not own the participant must not move it, got {:?}",
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
        // No `moved_to` label for the destination: the refusal wrote nothing
        // a later Join of the target could be relabelled by (merge slice
        // M2A-3; voice-move's `moved_from` marker is not ported).
        assert_eq!(
            get_user_moved_to_voice(f.dest.id(), &f.target.id)
                .await
                .expect("marker read"),
            None,
            "the refused move must not label the destination"
        );

        // A moderator's move is not a join by the target: it passes, and the
        // token goes to the bound session (pinned in the database crate,
        // `a_device_qualified_move_token_goes_to_the_bound_session_only`).
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

        // A bare participant has no device to impersonate, but the session
        // that owns it obeys the move, so the web session is still refused
        // (it used to pass here: lane 6a2's stolen-session steer). The owning
        // session moves itself. It rejoined bare, so that is how it is
        // recorded now.
        delete_voice_participant_identity(f.source.id(), &f.target.id)
            .await
            .expect("drop mapping");
        set_voice_participant_session(f.source.id(), &f.target.id, &bound.id, None)
            .await
            .expect("bare session record");
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
            "a session that does not own a bare participant must not move it, got {:?}",
            error
        );
        let response = move_member(
            &f.harness,
            &bound.token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;

        f.cleanup().await;
    }

    #[test]
    fn a_bare_self_move_from_another_session_is_refused() {
        crate::util::test::rt().block_on(a_bare_self_move_from_another_session_is_refused_case())
    }

    /// Lane 6a2, the same class as media-e2ee final audit F1. The target is
    /// in the call BARE from session A (`target_token`; the fixture records
    /// it). Session B of the same user moving them would steer A, which obeys
    /// the move event, so B is refused, and refused BEFORE the member
    /// document is written (merge slice SEC3-1: the route's own owner check,
    /// ahead of `member.update`; the move's check alone would refuse only
    /// after the rest of the PATCH was applied). A passes the check and every
    /// other one. With no record, nobody may self-move; a moderator still
    /// may.
    ///
    /// The carry of A's session to the destination (lane 6a3) happens inside
    /// the move after the SFU listing, which the absent node never reaches:
    /// pinned in the database crate
    /// (`a_move_carries_the_session_record_only_while_the_source_names_it`,
    /// `a_self_move_is_refused_unless_it_comes_from_the_owning_session`).
    async fn a_bare_self_move_from_another_session_is_refused_case() {
        let f = move_fixture(true).await;
        let account = f
            .harness
            .db
            .fetch_account(&f.target.id)
            .await
            .expect("account");
        let other = account
            .create_session(&f.harness.db, String::new())
            .await
            .expect("session B");

        // Session B, with an edit it may make on its own riding along: the
        // refusal must apply none of it.
        let response = edit_member(
            &f.harness,
            &other.token,
            &f.server.id,
            &f.target.id,
            serde_json::json!({ "voice_channel": f.dest.id(), "pronouns": "they/them" }),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Unauthorized, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::NotAuthenticated),
            "a session that does not own the participant must not move it, got {:?}",
            error
        );
        assert_eq!(
            f.harness
                .db
                .fetch_member(&f.server.id, &f.target.id)
                .await
                .expect("member read")
                .pronouns,
            None,
            "a refused self-move must leave the member document untouched"
        );
        assert!(
            get_voice_state(&f.source_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused move must leave the target connected"
        );
        // Nothing written for the destination: no `moved_to` label (merge
        // slice M2A-3; voice-move's `moved_from` marker is not ported) and no
        // session carried over.
        assert_eq!(
            get_user_moved_to_voice(f.dest.id(), &f.target.id)
                .await
                .expect("marker read"),
            None,
            "the refused move must not label the destination"
        );
        assert_eq!(
            recorded_session(&f.dest, &f.target.id).await,
            None,
            "the refused move must not carry a session over"
        );

        // The owning session clears the check and every other one, up to the
        // absent node.
        let response = move_member(
            &f.harness,
            &f.target_token,
            &f.server.id,
            &f.target.id,
            f.dest.id(),
        )
        .await;
        assert_reached_livekit(response).await;
        assert_eq!(
            recorded_session(&f.source, &f.target.id).await,
            Some(f.target_session.clone()),
            "the source record stays while the participant is still there"
        );

        // The record is gone (a join from before it existed): the owner is
        // unknown, so no session may self-move.
        forget_session_record(&f.source, &f.target.id).await;
        for token in [&f.target_token, &other.token] {
            let response =
                move_member(&f.harness, token, &f.server.id, &f.target.id, f.dest.id()).await;
            let (status, error) = error_of(response).await;
            assert_eq!(status, Status::Unauthorized, "{error:?}");
            assert!(
                matches!(error, revolt_result::ErrorType::NotAuthenticated),
                "with no recorded owner a self-move must be refused, got {:?}",
                error
            );
        }

        // A moderator's move is not a join by the target: unaffected (with
        // no owner the move becomes a disconnect, `Disconnected`, which the
        // absent node refuses first here, like every other move).
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
    fn a_sibling_self_move_is_refused_even_when_the_target_holds_move_members() {
        crate::util::test::rt()
            .block_on(a_sibling_self_move_is_refused_even_when_the_target_holds_move_members_case())
    }

    /// Merge slice SEC6-2, SEC3-1's exact attack: the TARGET holds
    /// `MoveMembers` on both the source and the destination, and a session
    /// of theirs that does not own the participant asks to move them. Moving
    /// yourself is a self-move whatever you hold, so it is refused
    /// `NotAuthenticated` by the owner check, before the member document is
    /// written: the nickname and pronouns sent with it are not applied. A
    /// policy decided from the caller's permissions would call this a
    /// moderator's move, skip the owner check and steer the owning session
    /// into a channel it never chose (control SEC6-2).
    async fn a_sibling_self_move_is_refused_even_when_the_target_holds_move_members_case() {
        use revolt_database::util::permissions::DatabasePermissionQuery;
        use revolt_permissions::calculate_channel_permissions;

        let f = move_fixture(true).await;
        let moderator = ranked_role(
            &f.harness,
            &f.server,
            2,
            ChannelPermission::MoveMembers as u64 | ChannelPermission::ChangeNickname as u64,
        )
        .await;
        give_role(&f.harness, &f.server, &f.target, &moderator).await;
        for channel in [&f.source, &f.dest] {
            let mut query = DatabasePermissionQuery::new(&f.harness.db, &f.target).channel(channel);
            assert!(
                calculate_channel_permissions(&mut query)
                    .await
                    .has_channel_permission(ChannelPermission::MoveMembers),
                "the target must hold MoveMembers on {}",
                channel.id()
            );
        }

        let sibling = f
            .harness
            .db
            .fetch_account(&f.target.id)
            .await
            .expect("account")
            .create_session(&f.harness.db, String::new())
            .await
            .expect("sibling session");
        let response = edit_member(
            &f.harness,
            &sibling.token,
            &f.server.id,
            &f.target.id,
            serde_json::json!({
                "voice_channel": f.dest.id(),
                "nickname": "Sibling",
                "pronouns": "they/them",
            }),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::Unauthorized, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::NotAuthenticated),
            "a sibling session must not self-move the participant, whatever \
             the target holds, got {:?}",
            error
        );

        let member = f
            .harness
            .db
            .fetch_member(&f.server.id, &f.target.id)
            .await
            .expect("member read");
        assert_eq!(
            (member.nickname, member.pronouns),
            (None, None),
            "the refused self-move must leave the member document untouched"
        );
        assert!(
            get_voice_state(&f.source_uvc, &f.target.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused move must leave the target connected"
        );
        assert_eq!(
            recorded_session(&f.source, &f.target.id).await,
            Some(f.target_session.clone()),
            "the owning session's record is untouched"
        );
        assert_eq!(
            recorded_session(&f.dest, &f.target.id).await,
            None,
            "the refused move must not carry a session over"
        );

        f.cleanup().await;
    }

    #[test]
    fn a_bot_edit_needs_no_session() {
        crate::util::test::rt().block_on(a_bot_edit_needs_no_session_case())
    }

    /// Bots authenticate with `x-bot-token` and have no session. Their edits
    /// keep working; a move of a bot is refused `IsBot` (ruling 09-27, merge
    /// slice P2A-16), whether the bot moves itself (device-qualified or bare:
    /// with no session there is no owner to match either way) or a moderator
    /// moves it (with no owner it would silently become a disconnect). The
    /// moderator can still disconnect it.
    async fn a_bot_edit_needs_no_session_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, owner) = harness.new_user().await;
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
        assert_eq!(status, Status::BadRequest, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::IsBot),
            "a bot moving its device identity must be refused IsBot, got {:?}",
            error
        );

        // Bare, too.
        delete_voice_participant_identity(source.id(), &bot_user.id)
            .await
            .expect("drop mapping");
        let response = harness
            .client
            .patch(format!("/servers/{}/members/{}", server.id, bot_user.id))
            .header(ContentType::JSON)
            .header(Header::new("x-bot-token", bot.token.clone()))
            .body(serde_json::json!({ "voice_channel": dest.id() }).to_string())
            .dispatch()
            .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::IsBot),
            "a bot moving its bare identity must be refused IsBot, got {:?}",
            error
        );

        // A moderator (the owner) moving the bot: refused the same way, and
        // before the member document is written, so a nickname sent with it
        // is not applied.
        let response = edit_member(
            &harness,
            &session_a.token,
            &server.id,
            &bot_user.id,
            serde_json::json!({ "voice_channel": dest.id(), "nickname": "Moved" }),
        )
        .await;
        let (status, error) = error_of(response).await;
        assert_eq!(status, Status::BadRequest, "{error:?}");
        assert!(
            matches!(error, revolt_result::ErrorType::IsBot),
            "a moderator's move of a bot must be refused IsBot, got {:?}",
            error
        );
        assert_eq!(
            harness
                .db
                .fetch_member(&server.id, &bot_user.id)
                .await
                .expect("member read")
                .nickname
                .as_deref(),
            Some("Botty"),
            "the refused move must leave the member document untouched"
        );
        assert!(
            get_voice_state(&source_uvc, &bot_user.id)
                .await
                .expect("voice state read")
                .is_some(),
            "the refused moves must leave the bot connected"
        );

        // The moderator can still disconnect it. With no node behind the
        // call there is nothing to evict, and the bot's state is torn down.
        delete_channel_node(source.id()).await.expect("drop node");
        let response =
            disconnect_member(&harness, &session_a.token, &server.id, &bot_user.id).await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "disconnecting a bot must still work, got {:?}",
            response.into_string().await
        );
        assert!(
            get_voice_state(&source_uvc, &bot_user.id)
                .await
                .expect("voice state read")
                .is_none(),
            "the disconnect must take the bot out of the call"
        );

        delete_channel_voice_state(&source_uvc, &[bot_user.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn a_privileged_non_member_target_is_not_found() {
        crate::util::test::rt().block_on(a_privileged_non_member_target_is_not_found_case())
    }

    /// Merge slice SEC2-5: the permission calculus waves a privileged
    /// account through before it looks at membership, so the move in the
    /// database crate checks membership itself
    /// (`a_privileged_non_member_is_not_found_for_a_move` there). This route
    /// never gets that far with such a target: it resolves the target as a
    /// MEMBER of the server first (`as_member`), so a platform-staff account
    /// that is in a call here but holds no membership answers `NotFound`
    /// before any voice read, for a moderator's move, the account's own
    /// self-move and a disconnect alike.
    async fn a_privileged_non_member_target_is_not_found_case() {
        use revolt_database::voice::set_voice_participant_session;

        let f = move_fixture(true).await;
        let (_s, session_s, mut staff) = f.harness.new_user().await;
        staff
            .update(
                &f.harness.db,
                revolt_database::PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged staff");
        assert!(
            f.harness
                .db
                .fetch_member(&f.server.id, &staff.id)
                .await
                .is_err(),
            "staff must hold no membership here"
        );
        create_voice_state(&f.source_uvc, &staff.id, Timestamp::now_utc())
            .await
            .expect("staff voice state");
        set_voice_participant_session(f.source.id(), &staff.id, &session_s.id, None)
            .await
            .expect("staff session record");

        for (token, body, who) in [
            (
                &f.mod_token,
                serde_json::json!({ "voice_channel": f.dest.id() }),
                "a moderator's move",
            ),
            (
                &session_s.token,
                serde_json::json!({ "voice_channel": f.dest.id() }),
                "the account's own move",
            ),
            (
                &f.mod_token,
                serde_json::json!({ "remove": ["VoiceChannel"] }),
                "a moderator's disconnect",
            ),
        ] {
            let response = edit_member(&f.harness, token, &f.server.id, &staff.id, body).await;
            let (status, error) = error_of(response).await;
            assert_eq!(status, Status::NotFound, "{who}: {error:?}");
            assert!(
                matches!(error, revolt_result::ErrorType::NotFound),
                "{who} of a privileged non-member must be NotFound, got {:?}",
                error
            );
        }
        assert!(
            get_voice_state(&f.source_uvc, &staff.id)
                .await
                .expect("voice state read")
                .is_some(),
            "nothing may have touched the staff account's call"
        );

        delete_channel_voice_state(&f.source_uvc, &[staff.id.clone()])
            .await
            .expect("cleanup staff");
        f.cleanup().await;
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

    /// Connect `user_id` to `channel` as a publishing participant on a node,
    /// from a session `join_call` records as the owner of the participant
    /// (seated bare), as every join since the merge slice does. Without the
    /// record a moderator's move of this participant would be a move nobody
    /// can be told about, done as a disconnect (merge slice m1_rt LOW).
    async fn connect_publishing(channel: &Channel, user_id: &str) -> UserVoiceChannel {
        let uvc = UserVoiceChannel::from_channel(channel);

        revolt_database::voice::set_voice_participant_session(
            channel.id(),
            user_id,
            &format!("FIXTURESESSION{user_id}"),
            None,
        )
        .await
        .expect("session record");

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
    fn platform_staff_can_act_on_an_owner_with_no_roles() {
        crate::util::test::rt()
            .block_on(platform_staff_can_act_on_an_owner_with_no_roles_case())
    }

    /// The owner now ranks `i64::MIN`, and platform staff resolve no member
    /// rank (also `i64::MIN`), so without the `!user.privileged` exemption on
    /// the rank check staff would be refused `NotElevated` against every
    /// server owner. The exemption keeps the reach staff already had.
    async fn platform_staff_can_act_on_an_owner_with_no_roles_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner, no roles
        let (_s, session_s, mut staff) = harness.new_user().await; // staff, not a member
        let (server, _channels) = harness.new_server(&user_a).await;

        // The harness inserts the server without the owner's membership,
        // which a real server always has.
        if harness.db.fetch_member(&server.id, &user_a.id).await.is_err() {
            Member::create(&harness.db, &server, &user_a, None)
                .await
                .expect("owner member");
        }

        staff
            .update(
                &harness.db,
                revolt_database::PartialUser {
                    privileged: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("privileged staff");
        assert!(
            harness.db.fetch_member(&server.id, &staff.id).await.is_err(),
            "staff must hold no membership here, so they resolve no member rank"
        );

        let owner = harness
            .db
            .fetch_member(&server.id, &user_a.id)
            .await
            .expect("owner member");
        assert!(owner.roles.is_empty(), "the owner must hold no roles here");

        let response = edit_member(
            &harness,
            &session_s.token,
            &server.id,
            &user_a.id,
            serde_json::json!({
                "can_publish": false,
                "nickname": "renamed"
            }),
        )
        .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "platform staff must pass the rank check against a roleless owner"
        );

        let owner = harness
            .db
            .fetch_member(&server.id, &user_a.id)
            .await
            .expect("owner member");
        assert!(!owner.can_publish, "the staff mute must have landed");
        assert_eq!(
            owner.nickname.as_deref(),
            Some("renamed"),
            "the staff rename must have landed"
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

    /// This file's shipping text, the test module cut off, comments kept.
    fn shipping_text() -> &'static str {
        let source = include_str!("member_edit.rs");
        &source[..source.find("#[cfg(test)]").expect("test module")]
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
    ///
    /// Merge slice: the gate carries the server-scoped `MoveMembers`
    /// fallback for a target in no call (RT-4), and the carry out of the
    /// destination block carries the owning session read once from the
    /// gated source (RT-2) and the self-move owner check (SEC3-1); the move
    /// expects that session and runs under the one `policy`.
    ///
    /// Operator ruling 2026-09-28 (merge slice FXA-1): the gate's first step
    /// asks whether the mover can see the source, of the channel it already
    /// resolved; a source they cannot see becomes `None` (no call) before
    /// the source gate, and the fallback then decides on that `None`. Still
    /// one pointer read. Mutations: the hidden branch removed, so a hidden
    /// source goes through the source gate again (control HIDDEN-GATED), or
    /// kept as the source (control HIDDEN-EVICTS).
    #[test]
    fn the_move_expects_the_source_the_mover_was_gated_on() {
        const READ: &str = "let source_id = \
             get_user_voice_channel_in_server(&target_user.id, &server.id).await?;";
        const GATE: &str = "let source_id = match source_id \u{7b} \
             Some(source_id) => \u{7b} \
             let source = Reference::from_unchecked(&source_id).as_channel(db).await?; \
             if member.id.user != user.id \
             && !mover_can_see_source(db, &user, &source).await \u{7b} None \u{7d} \
             else \u{7b} if member.id.user != user.id \u{7b} \
             assert_mover_may_move_out_of(db, &user, &source).await?; \u{7d} \
             Some(source_id) \u{7d} \u{7d} None => None, \u{7d}; \
             if source_id.is_none() && member.id.user != user.id \u{7b} \
             permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?; \
             \u{7d}";
        const CARRY: &str = "let Some(source_id) = source_id.clone() else \u{7b} \
             return Err(create_error!(NotConnected)); \u{7d}; \
             let expected_session = \
             get_voice_participant_session(&source_id, &target_user.id).await?; \
             if let MovePolicy::SelfMove \u{7b} request_session \u{7d} = policy \u{7b} \
             if source_id != channel.id() \
             && !self_move_from_owning_session(expected_session.as_deref(), request_session) \
             \u{7b} return Err(create_error!(NotAuthenticated)); \u{7d} \u{7d} \
             Some((channel, source_id, expected_session))";
        const MOVE: &str = "if let Some((new_voice_channel, source_id, expected_session)) = \
             new_voice_channel \u{7b} match move_user_to_voice_channel_expecting( db, \
             voice_client, &target_user, &new_voice_channel, &source_id, \
             expected_session.as_deref(), policy, ) .await? \u{7b}";

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
    /// switched away from the gated source after the precondition, or the
    /// owning session changed under the move) answers the same `NotConnected`
    /// error the precondition gives, and only `Moved` / `AlreadyPresent` /
    /// `Disconnected` (a moderator's move nobody could be told about, done as
    /// a disconnect) fall through to the 200. `TargetCannotJoin` (merge slice
    /// P2A-3 / M2B-1: a tokenless move into a channel `join_call` would refuse
    /// the target, refused before any write) answers `CannotJoinCall`, an
    /// existing error `join_call` itself gives. Mutations: the `NotConnected`
    /// or `TargetCannotJoin` arm turned into `{}` or folded into the 200 arm
    /// (control TCJ-OK), `Disconnected` turned into an error (control
    /// DISCONNECTED-ERR), a `_ => {}` catch-all, or the outcome dropped again
    /// with `.await?;`.
    #[test]
    fn a_move_that_did_not_happen_is_an_error() {
        const OUTCOME: &str = "&source_id, expected_session.as_deref(), policy, ) .await? \u{7b} \
             VoiceMoveOutcome::Moved \u{7b} .. \u{7d} | VoiceMoveOutcome::AlreadyPresent \
             | VoiceMoveOutcome::Disconnected => \u{7b}\u{7d} \
             VoiceMoveOutcome::NotConnected => return Err(create_error!(NotConnected)), \
             VoiceMoveOutcome::TargetCannotJoin => return Err(create_error!(CannotJoinCall)), \
             \u{7d}";

        let body = route_body();
        assert_eq!(
            body.matches(OUTCOME).count(),
            1,
            "the move's outcome must be matched, with `NotConnected` and \
             `TargetCannotJoin` errors: {body}"
        );
        assert_eq!(
            body.matches("VoiceMoveOutcome::").count(),
            5,
            "exactly the five variants, no catch-all: {body}"
        );
    }

    /// Merge slice SEC3-1 (P-POLICY): the move policy is bound ONCE, from
    /// `member.id.user == user.id` alone (a self-move is a `SelfMove` whatever
    /// the caller's permissions, carrying the caller's own session), and that
    /// one binding goes to the pre-flight and to the move. Nothing else in
    /// the file builds a policy, and the sweep's is never used here.
    /// Mutations: the self-move arm replaced by `MovePolicy::Moderator`
    /// (control SEC3-1), the pre-flight handed a `MovePolicy::Moderator`
    /// literal while the move keeps `policy` (control POLICY-SPLIT), a second
    /// `let policy`, the session filter dropped.
    #[test]
    fn the_move_policy_is_decided_by_who_is_moved_alone() {
        const REQUEST: &str = "let request_session = session .as_ref() \
             .filter(|session| session.user_id == user.id) \
             .map(|session| session.id.as_str());";
        const POLICY: &str = "let policy = if member.id.user == user.id \u{7b} \
             MovePolicy::SelfMove \u{7b} request_session \u{7d} \u{7d} else \u{7b} \
             MovePolicy::Moderator \u{7d};";
        const PREFLIGHT: &str =
            "assert_voice_move_admissible(db, &target_user, &channel, policy).await?;";
        const TO_THE_MOVE: &str = "expected_session.as_deref(), policy, ) .await?";

        let body = route_body();
        let mut last = 0;
        for needle in [REQUEST, POLICY, PREFLIGHT, TO_THE_MOVE] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the route must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last <= at, "`{}` is out of order: {}", needle, body);
            last = at;
        }

        for (needle, want) in [
            ("let policy", 1),
            ("assert_voice_move_admissible(", 1),
            ("MovePolicy::Moderator", 1),
            // The binding, and the owner check's match on that binding.
            ("MovePolicy::SelfMove", 2),
            ("MovePolicy::Sweep", 0),
        ] {
            assert_eq!(
                body.matches(needle).count(),
                want,
                "`{needle}` in the route: {body}"
            );
        }
        for (needle, want) in [("MovePolicy::", 3), ("MovePolicy::Sweep", 0)] {
            assert_eq!(
                shipping_text().matches(needle).count(),
                want,
                "`{needle}` in member_edit.rs outside its tests"
            );
        }
    }

    /// Merge slice RT-2 (P-READ): the session that owns the target's
    /// participant is read exactly ONCE in the route, from the gated source,
    /// for EVERY move (the read sits straight after the move's
    /// `NotConnected` precondition, outside the self-move branch), and that
    /// value, never the request's session, is what the move expects. Read
    /// only for self-moves, a moderator's move would reach the move with no
    /// owner and become a disconnect. The route adds no second read of its
    /// own (merge slice SEC5-4: `voice_participant_session_is` stays the
    /// database crate's; the owner check decides on this one value).
    /// Mutations: `expected_session` taken from the request (control
    /// SESSION-FROM-REQUEST), the read moved into the self-move branch, a
    /// second read.
    #[test]
    fn the_route_reads_the_owning_session_once_for_every_move() {
        const READ: &str = "return Err(create_error!(NotConnected)); \u{7d}; \
             let expected_session = \
             get_voice_participant_session(&source_id, &target_user.id).await?; \
             if let MovePolicy::SelfMove \u{7b} request_session \u{7d} = policy \u{7b}";

        let body = route_body();
        assert_eq!(
            body.matches(READ).count(),
            1,
            "one unconditional read of the gated source's record, ahead of the self-move \
             branch: {body}"
        );
        for (needle, want) in [
            ("let expected_session", 1),
            ("Some((channel, source_id, expected_session))", 1),
            (
                "if let Some((new_voice_channel, source_id, expected_session))",
                1,
            ),
            (
                "self_move_from_owning_session(expected_session.as_deref(), request_session)",
                1,
            ),
            ("&source_id, expected_session.as_deref(), policy, )", 1),
            // The five above, and nowhere else.
            ("expected_session", 5),
        ] {
            assert_eq!(
                body.matches(needle).count(),
                want,
                "`{needle}` in the route: {body}"
            );
        }
        for (needle, want) in [
            ("get_voice_participant_session(", 1),
            ("get_voice_participant_session_seat(", 0),
            ("voice_participant_session_is(", 0),
        ] {
            assert_eq!(
                crate::util::test::without_comments(shipping_text())
                    .matches(needle)
                    .count(),
                want,
                "`{needle}` in member_edit.rs outside its tests"
            );
        }
    }

    /// Merge slice SEC3-1 (P-OWNER) and the bot ruling (P-BOT): a self-move
    /// from a session that does not own the participant, and any move of a
    /// bot, are refused BEFORE the member document is written, so nothing
    /// else in the same PATCH is applied. The move refuses a non-owner
    /// self-move too, but only after the write. The bot refusal sits in the
    /// move branch only, so a bot can still be disconnected. Mutations: the
    /// owner check moved after `member.update` (control OWNER-LATE) or
    /// dropped (control OWNER-DROP); the bot refusal dropped (control
    /// NO-BOT).
    #[test]
    fn a_refused_self_move_or_bot_move_writes_nothing() {
        const MOVE_BRANCH: &str =
            "let new_voice_channel = if let Some(new_channel) = &data.voice_channel \u{7b}";
        const BOT: &str = "if target_user.bot.is_some() \u{7b} \
             return Err(create_error!(IsBot)); \u{7d}";
        const PREFLIGHT: &str = "assert_voice_move_admissible(";
        const OWNER: &str = "if let MovePolicy::SelfMove \u{7b} request_session \u{7d} = policy \
             \u{7b} if source_id != channel.id() \
             && !self_move_from_owning_session(expected_session.as_deref(), request_session) \
             \u{7b} return Err(create_error!(NotAuthenticated)); \u{7d} \u{7d}";
        // The member write, as far as rustfmt cannot rewrap it.
        const WRITE: &str = "member .update(";

        let body = route_body();
        let mut last = 0;
        for needle in [MOVE_BRANCH, BOT, PREFLIGHT, OWNER, WRITE] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the route must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        for (needle, want) in [
            ("self_move_from_owning_session(", 1),
            ("IsBot", 1),
            (".bot.", 1),
        ] {
            assert_eq!(
                body.matches(needle).count(),
                want,
                "`{needle}` in the route: {body}"
            );
        }
    }

    /// Ruling D0-3 / merge slice RT-4 (P-SERVER-MM): `MoveMembers` is decided
    /// per channel, and the server-scoped check survives only as the fallback
    /// for somebody else's move or disconnect of a target in no call (or in a
    /// call hidden from them, merge slice FXA-1, which is `None` by then).
    /// Mutation: the unconditional server-scoped check restored ahead of the
    /// source gate (control SERVER-MM-BACK).
    #[test]
    fn server_scoped_move_members_is_only_the_no_source_fallback() {
        const FALLBACK: &str = "if source_id.is_none() && member.id.user != user.id \u{7b} \
             permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?; \
             \u{7d}";

        let body = route_body();
        assert_eq!(
            body.matches(FALLBACK).count(),
            1,
            "the no-source fallback: {body}"
        );
        assert_eq!(
            body.matches("ChannelPermission::MoveMembers").count(),
            1,
            "no other server-scoped MoveMembers check in the route: {body}"
        );
    }

    /// Ruling 09-27 (P-MOVER-CONNECT): the mover needs `ViewChannel`,
    /// `MoveMembers` AND `Connect` on the destination, computed with the
    /// destination's overrides. Mutation: the Connect check dropped (control
    /// NO-MOVER-CONNECT; `move_needs_the_mover_to_connect_to_the_destination`
    /// goes red with it).
    #[test]
    fn the_mover_needs_connect_on_the_destination() {
        let body = shipping_fn("assert_mover_may_move_into");
        for needle in [
            "calculate_channel_permissions(&mut query)",
            "permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;",
            "permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;",
            "permissions.throw_if_lacking_channel_permission(ChannelPermission::Connect)?;",
        ] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the destination gate must carry `{needle}` exactly once: {body}"
            );
        }
    }

    /// Merge slice M2C-1: the source gate asks `MoveMembers` BEFORE
    /// `ViewChannel`, so it fails on the same check, with the same error, as
    /// the no-source fallback. Exactly two checks, computed with the
    /// source's overrides, in that order. Mutation: the two checks swapped
    /// back (control ORACLE).
    ///
    /// Since the FXA-1 ruling this pin is the only thing ORACLE turns red. A
    /// call hidden from the mover never reaches the gate any more (it is no
    /// call, and the fallback answers), and on a call the mover can see
    /// `ViewChannel` always passes, so no request can observe the order: the
    /// two `..._does_not_say_where_the_target_is` tests stay green under
    /// ORACLE. The order is kept, and pinned, so that the gate still answers
    /// like the fallback if the call site ever stops asking `ViewChannel`
    /// first.
    #[test]
    fn the_source_gate_asks_move_members_first() {
        const MOVE_MEMBERS: &str =
            "permissions.throw_if_lacking_channel_permission(ChannelPermission::MoveMembers)?;";
        const VIEW_CHANNEL: &str =
            "permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;";

        let body = shipping_fn("assert_mover_may_move_out_of");
        for needle in [
            "DatabasePermissionQuery::new(db, user).channel(source);",
            "calculate_channel_permissions(&mut query)",
            MOVE_MEMBERS,
            VIEW_CHANNEL,
        ] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the source gate must carry `{needle}` exactly once: {body}"
            );
        }
        assert_eq!(
            body.matches("throw_if_lacking_channel_permission(").count(),
            2,
            "the source gate asks exactly two permissions: {body}"
        );
        assert!(
            body.find("calculate_channel_permissions(&mut query)") < body.find(MOVE_MEMBERS)
                && body.find(MOVE_MEMBERS) < body.find(VIEW_CHANNEL),
            "the source gate must ask MoveMembers first, then ViewChannel: {}",
            body
        );
    }

    /// Operator ruling 2026-09-28 (merge slice FXA-1): whether the mover can
    /// see the source is asked with the source's own overrides, of
    /// `ViewChannel` and nothing else, once, and only for somebody else's
    /// edit. A hidden source is then no call (its branch and the fallback are
    /// pinned in `the_move_expects_the_source_the_mover_was_gated_on`).
    /// Mutations: the hidden branch removed (control HIDDEN-GATED), the
    /// hidden source kept (control HIDDEN-EVICTS); both also go red on the
    /// route tests `a_mover_with_server_move_members_cannot_find_a_hidden_call_*`.
    #[test]
    fn a_source_the_mover_cannot_see_is_no_call() {
        let body = shipping_fn("mover_can_see_source");
        for needle in [
            "DatabasePermissionQuery::new(db, user).channel(source);",
            "calculate_channel_permissions(&mut query)",
            ".has_channel_permission(ChannelPermission::ViewChannel)",
        ] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the view check must carry `{needle}` exactly once: {body}"
            );
        }
        assert_eq!(
            body.matches("ChannelPermission::").count(),
            1,
            "the view check asks ViewChannel alone: {body}"
        );

        let route = route_body();
        for (needle, want) in [
            ("mover_can_see_source(", 1),
            (
                "if member.id.user != user.id \
                 && !mover_can_see_source(db, &user, &source).await \u{7b} None \u{7d}",
                1,
            ),
            ("assert_mover_may_move_out_of(", 1),
        ] {
            assert_eq!(
                route.matches(needle).count(),
                want,
                "`{needle}` in the route: {route}"
            );
        }
        assert!(
            route.find("mover_can_see_source(") < route.find("assert_mover_may_move_out_of("),
            "the view check decides before the source gate: {}",
            route
        );
    }

    /// Merge slice RB-H1 / P2A-13: voice-move parked its move-delivery
    /// helpers in this route; the delivery now lives in the database crate
    /// alone (`move_event_delivery`, `move_token_plan` and the owner check
    /// beside `move_addressing`), and so do the mint and the event. None of
    /// those, nor any of the NOT-PORTED names (the scoped teardown script,
    /// the `moved_from` marker, the route-level removal and its re-read), may
    /// come back into this file's shipping text, comments included.
    /// Mutation: one of them re-added (control BAN, `fn move_event_url`).
    #[test]
    fn member_edit_carries_none_of_the_unported_move_helpers() {
        let shipping = shipping_text();
        assert!(
            shipping.contains("pub async fn edit("),
            "the scan must see the route itself"
        );
        for banned in [
            "DELETE_SCOPED_VOICE_STATE_LUA",
            "get_user_moved_from_voice",
            "set_user_moved_from_voice",
            "move_event_url",
            "take_participant_out_of_source",
            "assert_voice_channel_unchanged",
            "SourceParticipant",
            "get_voice_participant_identity(",
            "qualified_move_device",
            "move_token_plan",
            "move_event_delivery",
            "fn self_move_from_owning_session",
            "create_token(",
            ".private(",
            ".private_session(",
            "UserMoveVoiceChannel",
            // The rest of voice-move's parked helpers.
            "MoveDelivery",
            "MoveTokenPlan",
            "fetch_device_identity",
        ] {
            assert!(
                !shipping.contains(banned),
                "member_edit.rs must not carry `{}` outside its tests: the move's \
                 delivery lives in the database crate only",
                banned
            );
        }
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
    ///
    /// Media-e2ee S6M-2 / SEC6-1: the target's session record for the gated
    /// source is dropped, exactly once, AFTER the recorded read and BEFORE
    /// the release and the eviction, with its `?`, so a failed drop refuses
    /// the disconnect with nothing evicted. Mutations: the drop deleted
    /// (control NODROP-DISC), the drop moved after the eviction (control
    /// DROPLATE-DISC); `a_disconnect_drops_the_targets_session_record_first`
    /// goes red with both.
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
        const DROP: &str = "drop_voice_participant_session(channel, &target_user.id).await?;";
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
            SOURCE, RECORDED, HOLDS, NODE, DROP, RELEASE, EVICT, SKIP, TEARDOWN,
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
        // The drop, once, and only here: the move path must not drop the
        // record it hands the move as the expected owner.
        assert_eq!(
            body.matches("drop_voice_participant_session(").count(),
            1,
            "one record drop in the route, in the disconnect: {body}"
        );
        let order: Vec<usize> = [
            "recorded_voice_connections(",
            "drop_voice_participant_session(",
            "release_remote_control_for_user(",
            "remove_user_if_present_sids(",
        ]
        .iter()
        .map(|needle| block.find(needle).expect("pinned above"))
        .collect();
        assert!(
            order.windows(2).all(|pair| pair[0] < pair[1]),
            "the recorded read, then the drop, then the release, then the \
             eviction: {}",
            block
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
    fn a_source_the_mover_cannot_see_is_answered_as_no_call() {
        crate::util::test::rt()
            .block_on(a_source_the_mover_cannot_see_is_answered_as_no_call_case())
    }

    /// The mover's own standing on the SOURCE — the call the target is being
    /// pulled out of — which nothing checked at all.
    ///
    /// Same construction as the destination test, and for the same reason the
    /// moderator is not the owner: the calculus short-circuits to GrantAllSafe
    /// for an owner before any override is read. They hold `MoveMembers` from
    /// a server role and the SOURCE denies that role `ViewChannel`. Server
    /// scoped that is a pass. Without a check on the source, a moderator
    /// explicitly locked out of a private voice channel could empty it into
    /// a channel they do control.
    ///
    /// Operator ruling 2026-09-28 (merge slice FXA-1): a source the mover
    /// cannot see is, for them, no call, so neither shape reaches into it. The
    /// move is refused exactly as the move of a target in no call is
    /// (`NotConnected`), and the disconnect is the same 200 no-op, so
    /// neither says who sits in the channel. It used to be refused with a
    /// 403 from the source gate, and that 403, next to a no-call target's
    /// 200 or `NotConnected`, was the answer that DID say it. Byte-identical
    /// to the no-call answers in
    /// `a_mover_with_server_move_members_cannot_find_a_hidden_call_*`; a
    /// source the mover can see and is denied `MoveMembers` on is still
    /// refused by the gate (`move_needs_move_members_on_the_source_channel`).
    ///
    /// Both shapes that reach into the source are covered: the move, and the
    /// `remove: ["VoiceChannel"]` disconnect, and after both the target is
    /// still connected, with the session record that owns them. Renamed from
    /// `move_is_refused_when_the_mover_is_denied_the_source` (media-e2ee
    /// S6R-6): the move is no longer refused as such, it is answered as no
    /// call.
    async fn a_source_the_mover_cannot_see_is_answered_as_no_call_case() {
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

        // The SOURCE denies the moderator's role `ViewChannel`. The
        // destination is untouched, and so is the target's own standing, so
        // what changes below is the source alone.
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

        // The move is the move of a target in no call: `NotConnected`,
        // answered after the destination gates, with nothing moved.
        let response = move_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            destination.id(),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "NotConnected").await;

        // The disconnect shape reaches into the same channel, and is the
        // no-op a disconnect of a target in no call is.
        let response = edit_member(
            &harness,
            &session_b.token,
            &server.id,
            &user_c.id,
            serde_json::json!({ "remove": ["VoiceChannel"] }),
        )
        .await;
        assert_eq!(
            response.status(),
            Status::Ok,
            "a disconnect out of a source the mover cannot see is a no-op: {:?}",
            response.into_string().await
        );

        // ...and the target is still where they were, in both cases, owned
        // by the same session.
        assert!(
            is_publishing(&source_uvc, &user_c.id).await,
            "neither shape may take the target out of a call the mover cannot see"
        );
        assert_eq!(
            revolt_database::voice::get_voice_participant_session(source.id(), &user_c.id)
                .await
                .expect("session record read"),
            Some(format!("FIXTURESESSION{}", user_c.id)),
            "neither shape may drop the record of a call the mover cannot see"
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
