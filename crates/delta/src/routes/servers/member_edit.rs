use std::collections::HashSet;

use revolt_database::{
    util::{
        name_filter::contains_blocked_slur, permissions::DatabasePermissionQuery,
        reference::Reference,
    },
    voice::{
        assert_voice_move_admissible, get_channel_node, get_user_voice_channel_in_server,
        move_user_to_voice_channel, sync_user_voice_permissions, UserVoiceChannel, VoiceClient,
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

    if data.voice_channel.is_some() || data.remove.contains(&FieldsMember::VoiceChannel) {
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
        // decided here too — its own `remove_user` runs after the member
        // document has already been written.
        //
        // No source means the target is in no call in this server; there is
        // nothing to be gated on, and the move branch below still answers
        // `NotConnected` in its own place. An unresolvable source channel
        // propagates rather than being waved through: a gate whose subject
        // cannot be read refuses.
        if let Some(source_id) =
            get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            let source = Reference::from_unchecked(&source_id).as_channel(db).await?;

            // Self-move exemption, same as the destination gate: leaving a
            // call you are in is not exercising `MoveMembers` over anybody.
            if member.id.user != user.id {
                assert_mover_may_move_out_of(db, &user, &source).await?;
            }
        }
    }

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
        // The property survives `move_user_to_voice_channel` re-deciding all
        // of it AFTER the write only because a PATCH may not combine
        // `voice_channel` with the fields that change these permissions (see
        // the refusal above). Without that, the second reading could refuse
        // an edit the first admitted, leaving it applied and the move not
        // made.
        //
        // `move_user_to_voice_channel` runs the identical set again when it
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
        // This re-reads the key the source-side gate already read. Deliberate:
        // the gate has to run in the block the disconnect shape passes through
        // too, and the two reads race nothing that was not already racing —
        // `move_user_to_voice_channel` reads it a third time and is the only
        // reader whose answer is acted upon.
        if get_user_voice_channel_in_server(&target_user.id, &server.id)
            .await?
            .is_none()
        {
            Err(create_error!(NotConnected))?
        };

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
        // The move itself is server-authoritative and lives in the database
        // layer, because the AFK sweep needs the same behaviour with no
        // acting user and no Rocket request to hang it off. Everything that
        // is route policy — LiveKit being enabled, `MoveMembers`, ranking —
        // has already been decided above; everything that is about the move
        // being possible and safe is decided in there.
        //
        // `NotConnected` here is a race we lost (they left between the
        // precondition above and now) and `AlreadyPresent` means there was
        // nothing to do; neither is an error, and neither used to be
        // distinguishable — the old inline code silently no-op'd on the
        // first and evicted the member from their own call on the second.
        move_user_to_voice_channel(db, voice_client, &target_user, &new_voice_channel).await?;
    } else if affects_voice_permissions && !remove.contains(&FieldsMember::VoiceChannel) {
        // Skipped when the member is being disconnected outright just below —
        // syncing a participant we are about to evict is pointless, and a
        // failing sync would abort the request before the eviction ran.
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            let node = get_channel_node(&channel).await?.unwrap();
            let channel = Reference::from_unchecked(&channel).as_channel(db).await?;

            // Sync the TARGET being edited, not the acting moderator. Passing
            // `&user` here synced the moderator's own participant, and since
            // `sync_user_voice_permissions` early-returns for a user with no
            // voice state it usually did nothing at all — server-mute and
            // server-deafen never reached the target's SFU participant.
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
        };
    };

    if remove.contains(&FieldsMember::VoiceChannel) {
        if let Some(channel) = get_user_voice_channel_in_server(&target_user.id, &server.id).await?
        {
            let node = get_channel_node(&channel).await?.unwrap();

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
            // Whether the acting user may reach into this channel at all was
            // decided in the pre-flight, before the member document was
            // written — not here, where a refusal would be too late.
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
    use iso8601_timestamp::{Duration, Timestamp};
    use revolt_database::{
        events::client::EventV1,
        voice::{
            create_voice_state, delete_channel_voice_state, get_voice_state, set_channel_node,
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

    // ---- what the move refuses past the caps gate ------------------------
    //
    // Until these, nothing exercised the move beyond `assert_call_caps_admit`
    // — both move tests above stop there, and the `voice_channel` fixture is a
    // real voice channel, which is why the destination was never checked to be
    // one at all.

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

    #[test]
    fn move_is_refused_when_the_mover_is_denied_the_destination() {
        crate::util::test::rt().block_on(move_is_refused_when_the_mover_is_denied_the_destination_case())
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

    #[test]
    fn moving_a_member_to_the_channel_they_are_in_is_a_no_op() {
        crate::util::test::rt().block_on(moving_a_member_to_the_channel_they_are_in_is_a_no_op_case())
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
        // minted and — the point — `remove_user` never ran against the room
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
        // the same way — it used to run its `remove_user` with no
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

    #[test]
    fn moving_and_editing_voice_permissions_in_one_patch_is_refused() {
        crate::util::test::rt()
            .block_on(moving_and_editing_voice_permissions_in_one_patch_is_refused_case())
    }

    /// A move is decided twice — once side-effect free before the member
    /// document is written, once inside the move itself afterwards, against
    /// the member as they now stand. Combined with an edit that changes those
    /// very permissions the two readings disagree, and the disagreement is
    /// observable in both directions: grant-and-move is refused on pre-edit
    /// permissions, and timeout-and-move applies the timeout and then refuses
    /// the move, leaving a half-applied edit behind. Refusing the combination
    /// is what makes the route's ordering guarantee true.
    async fn moving_and_editing_voice_permissions_in_one_patch_is_refused_case() {
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

        let until = Timestamp::now_utc()
            .checked_add(Duration::hours(1))
            .expect("timeout timestamp");

        for body in [
            serde_json::json!({ "voice_channel": destination.id(), "roles": [] }),
            serde_json::json!({ "voice_channel": destination.id(), "timeout": until }),
            serde_json::json!({ "voice_channel": destination.id(), "can_publish": false }),
            serde_json::json!({ "voice_channel": destination.id(), "can_receive": false }),
            serde_json::json!({ "voice_channel": destination.id(), "remove": ["Roles"] }),
            serde_json::json!({ "voice_channel": destination.id(), "remove": ["Timeout"] }),
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
                "{body} moves the member and changes the permissions the move \
                 is decided under, and must be refused"
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
}
