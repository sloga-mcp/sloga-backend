use revolt_database::{
    util::{
        audit_reason::AuditLogReason, permissions::DatabasePermissionQuery, reference::Reference,
    },
    voice::{remove_user_from_server_voice, VoiceClient},
    AuditLogAction, AuditLogDraft, AuditLogEntry, Database, RemovalIntention, User,
};
use revolt_permissions::{calculate_server_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Kick Member
///
/// Removes a member from the server.
#[openapi(tag = "Server Members")]
#[delete("/<server_id>/members/<member_id>")]
pub async fn kick(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    server_id: Reference<'_>,
    member_id: Reference<'_>,
    reason: AuditLogReason,
) -> Result<EmptyResponse> {
    // Validated before anything else: a too-long reason must refuse the
    // kick, never answer 400 after it.
    let reason = reason.validated()?;

    let server = server_id.as_server(db).await?;

    if member_id.id == user.id {
        return Err(create_error!(CannotRemoveYourself));
    }

    if member_id.id == server.owner {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    calculate_server_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::KickMembers)?;

    let member = member_id.as_member(db, &server.id).await?;
    if member.get_ranking(query.server_ref().as_ref().unwrap())
        <= query.get_member_rank().unwrap_or(i64::MIN)
    {
        return Err(create_error!(NotElevated));
    }

    member
        .remove(db, &server, RemovalIntention::Kick, false)
        .await?;

    // Recorded once the kick is durable and BEFORE the eviction: a failed
    // eviction answers an error, but the kick it follows still happened. The
    // self-kick was refused above, so the actor is never the target.
    AuditLogEntry::record(
        db,
        AuditLogDraft {
            server: server.id.clone(),
            actor: Some(user.id.clone()),
            action: AuditLogAction::MemberKick,
            target: Some(member_id.id.to_string()),
            reason,
            ..Default::default()
        },
    )
    .await;

    // The membership is removed FIRST, so a rejoin racing this eviction is
    // refused by the join-time membership re-check (AFK S-3 D-3). Every call
    // in the server is reached, not only the one the per-server pointer names
    // (S-3 F-3).
    //
    // Residual (S-3 D-2): an eviction that fails here answers an error AFTER
    // the kick is durable, and a retried kick then answers NotFound, since
    // the target is no longer a member, so the retry cannot re-run the
    // eviction. The recovery is a ban, which evicts non-members too.
    remove_user_from_server_voice(db, voice_client, &server, member_id.id).await?;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_voice_state, get_user_voice_channel_in_server,
            get_voice_channel_members, is_in_voice_channel, record_voice_connection,
            recorded_voice_connections, set_channel_node, UserVoiceChannel,
        },
        AuditLogAction, AuditLogEntry, Channel, Member, PartialMember, PartialRole, Role, Server,
        User,
    };
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};

    // ---- behavior (needs RabbitMQ and Redis) ------------------------------
    //
    // Compile-only on a box without those services, like every other route
    // test. The eviction is observed through the ghost of an ended call: a
    // channel with NO node pinned, which `remove_user_from_server_voice`
    // reaches through the per-server pointer and tears down from the
    // recorded connections, with no SFU involved.

    /// A node name deliberately absent from `Revolt.toml`: an eviction
    /// addressed to it fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

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

    /// Whether any trace of `user_id` is left in `uvc`: a recorded
    /// connection, `vc:` membership, `vc_members:` membership, or the
    /// per-server pointer naming this channel.
    async fn voice_traces(uvc: &UserVoiceChannel, user_id: &str) -> (usize, bool, bool, bool) {
        let recorded = recorded_voice_connections(uvc, user_id)
            .await
            .expect("recorded read")
            .len();
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

    async fn kick<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        target_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .delete(format!("/servers/{server_id}/members/{target_id}"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
    }

    /// `kick` with an `X-Audit-Log-Reason` header, sent as given (the
    /// client percent-encodes it).
    async fn kick_with_reason<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
        target_id: &str,
        reason: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .delete(format!("/servers/{server_id}/members/{target_id}"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(Header::new("X-Audit-Log-Reason", reason.to_string()))
            .dispatch()
            .await
    }

    async fn assert_rejected(
        response: rocket::local::asynchronous::LocalResponse<'_>,
        status: Status,
        error_type: &str,
    ) {
        assert_eq!(response.status(), status);
        let body = response.into_string().await.unwrap_or_default();
        assert!(
            body.contains(error_type),
            "expected a {} error, got: {}",
            error_type,
            body
        );
    }

    /// Every audit log entry of `server_id`, newest first.
    async fn audit_entries(harness: &TestHarness, server_id: &str) -> Vec<AuditLogEntry> {
        harness
            .db
            .fetch_audit_log(server_id, None, 50, None, None)
            .await
            .expect("audit log read")
    }

    /// A role with explicit rank and permissions. `Role::create` derives the
    /// rank from the (stale) server passed in, so it is set here instead.
    async fn ranked_role(harness: &TestHarness, server: &Server, rank: i64, allow: i64) -> Role {
        let mut role = harness
            .new_role(server, rank, Some(OverrideField { a: allow, d: 0 }))
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

    async fn member_with_role(harness: &TestHarness, server: &Server, user: &User, role: &Role) {
        let (mut member, _) = Member::create(&harness.db, server, user, None)
            .await
            .expect("member");
        member
            .update(
                &harness.db,
                PartialMember {
                    roles: Some(vec![role.id.clone()]),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("role");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_kick_evicts_the_member() {
        crate::util::test::rt().block_on(a_kick_evicts_the_member_case())
    }

    /// AFK S-3 F-3: a kicked member's connections in the server's calls are
    /// torn down, here a ghost of an ended call with two recorded
    /// connections. Mutation: the eviction removed.
    async fn a_kick_evicts_the_member_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_kick_bare", &user_b.id).await;
        join_recorded(
            &uvc,
            &user_b.id,
            "PA_kick_device",
            &format!("{}:DEV", user_b.id),
        )
        .await;
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (2, true, true, true),
            "the ghost is in place"
        );

        let response = kick(&harness, &session_a.token, &server.id, &user_b.id).await;
        assert_eq!(response.status(), Status::NoContent, "the kick succeeds");

        assert!(harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_err());
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (0, false, false, false),
            "the kicked member's ghost must be torn down"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_kick_removes_the_membership_before_the_eviction() {
        crate::util::test::rt().block_on(a_kick_removes_the_membership_before_the_eviction_case())
    }

    /// AFK S-3 D-2: the membership goes first, so the join-time re-check
    /// refuses a rejoin that races the eviction. Observed with an eviction
    /// that fails (ABSENT_NODE, UnknownNode before any network): the error
    /// is answered, the membership is already gone, and the failed eviction
    /// tore nothing down. Mutation: the eviction moved above the membership
    /// removal.
    async fn a_kick_removes_the_membership_before_the_eviction_case() {
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

        let response = kick(&harness, &session_a.token, &server.id, &user_b.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        let body = response.into_string().await.unwrap_or_default();
        assert!(body.contains("UnknownNode"), "{}", body);

        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_err(),
            "the membership is removed before the eviction runs"
        );
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (1, true, true, true),
            "a failed eviction tears nothing down"
        );
        // The kick is durable, so it is in the audit log although the
        // eviction after it failed. Mutation: the record moved below the
        // eviction.
        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(
            entries.len(),
            1,
            "the durable kick is recorded: {:?}",
            entries
        );
        assert_eq!(entries[0].action, AuditLogAction::MemberKick);
        assert_eq!(entries[0].target.as_deref(), Some(user_b.id.as_str()));

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // ---- the audit log entry ----------------------------------------------

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_kick_records_one_member_kick_with_the_header_reason() {
        crate::util::test::rt()
            .block_on(a_kick_records_one_member_kick_with_the_header_reason_case())
    }

    /// A kick writes exactly one `member_kick` entry: the kicker as actor,
    /// the kicked user as target, no channel or changes, and the reason
    /// percent-decoded from the header.
    async fn a_kick_records_one_member_kick_with_the_header_reason_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let response = kick_with_reason(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            "kick%20reason",
        )
        .await;
        assert_eq!(response.status(), Status::NoContent, "the kick succeeds");
        assert!(harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_err());

        let entries = audit_entries(&harness, &server.id).await;
        assert_eq!(entries.len(), 1, "exactly one entry: {:?}", entries);
        let entry = &entries[0];
        assert_eq!(entry.server, server.id);
        assert_eq!(entry.action, AuditLogAction::MemberKick);
        assert_eq!(entry.actor.as_deref(), Some(user_a.id.as_str()));
        assert_eq!(entry.target.as_deref(), Some(user_b.id.as_str()));
        assert_eq!(entry.channel, None);
        assert!(entry.changes.is_empty(), "{:?}", entry.changes);
        assert_eq!(entry.count, None);
        assert_eq!(entry.reason.as_deref(), Some("kick reason"));
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_too_long_reason_refuses_the_kick() {
        crate::util::test::rt().block_on(a_too_long_reason_refuses_the_kick_case())
    }

    /// A 513-character reason is refused with AuditLogReasonTooLong before
    /// anything happens: the target is still a member and nothing is
    /// recorded. Mutation: the validation moved below the removal.
    async fn a_too_long_reason_refuses_the_kick_case() {
        let harness = TestHarness::new().await;
        let (_a, session_a, user_a) = harness.new_user().await; // owner
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let response = kick_with_reason(
            &harness,
            &session_a.token,
            &server.id,
            &user_b.id,
            &"a".repeat(513),
        )
        .await;
        assert_rejected(response, Status::BadRequest, "AuditLogReasonTooLong").await;

        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_ok(),
            "a refused kick must leave the target a member"
        );
        assert!(audit_entries(&harness, &server.id).await.is_empty());
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn kicking_the_owner_is_refused_and_records_nothing() {
        crate::util::test::rt().block_on(kicking_the_owner_is_refused_and_records_nothing_case())
    }

    /// The owner guard: a moderator holding KickMembers cannot kick the
    /// owner, and the refusal records nothing.
    async fn kicking_the_owner_is_refused_and_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_m, session_m, user_m) = harness.new_user().await; // moderator
        let (server, _channels) = harness.new_server(&user_a).await;
        let role = ranked_role(&harness, &server, 1, ChannelPermission::KickMembers as i64).await;
        member_with_role(&harness, &server, &user_m, &role).await;

        // `new_server` does not create the owner's member row (the create
        // route does that separately), so compare membership before and after
        // rather than assuming the owner is a member.
        let owner_was_member = harness
            .db
            .fetch_member(&server.id, &user_a.id)
            .await
            .is_ok();

        let response =
            kick_with_reason(&harness, &session_m.token, &server.id, &user_a.id, "owner").await;
        assert_rejected(response, Status::BadRequest, "InvalidOperation").await;

        assert_eq!(
            harness
                .db
                .fetch_member(&server.id, &user_a.id)
                .await
                .is_ok(),
            owner_was_member,
            "a refused owner kick must not change the owner's membership"
        );
        assert_eq!(
            harness
                .db
                .fetch_server(&server.id)
                .await
                .expect("server")
                .owner,
            user_a.id,
            "the owner is unchanged"
        );
        assert!(audit_entries(&harness, &server.id).await.is_empty());
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_kicker_not_above_the_target_is_refused_and_records_nothing() {
        crate::util::test::rt()
            .block_on(a_kicker_not_above_the_target_is_refused_and_records_nothing_case())
    }

    /// A moderator holding KickMembers whose role ranks below the target's
    /// (a larger rank number) is refused with NotElevated: the target is
    /// still a member and nothing is recorded.
    async fn a_kicker_not_above_the_target_is_refused_and_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_m, session_m, user_m) = harness.new_user().await; // moderator
        let (_b, _session_b, user_b) = harness.new_user().await; // target
        let (server, _channels) = harness.new_server(&user_a).await;
        let moderator =
            ranked_role(&harness, &server, 5, ChannelPermission::KickMembers as i64).await;
        let senior = ranked_role(&harness, &server, 1, 0).await;
        member_with_role(&harness, &server, &user_m, &moderator).await;
        member_with_role(&harness, &server, &user_b, &senior).await;

        let response =
            kick_with_reason(&harness, &session_m.token, &server.id, &user_b.id, "rank").await;
        assert_rejected(response, Status::Forbidden, "NotElevated").await;

        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_ok(),
            "a refused kick must leave the target a member"
        );
        assert!(audit_entries(&harness, &server.id).await.is_empty());
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_self_kick_is_refused_and_records_nothing() {
        crate::util::test::rt().block_on(a_self_kick_is_refused_and_records_nothing_case())
    }

    /// Kicking yourself is refused before anything happens, so there is
    /// never a self-targeted entry.
    async fn a_self_kick_is_refused_and_records_nothing_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // member
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let response =
            kick_with_reason(&harness, &session_b.token, &server.id, &user_b.id, "self").await;
        assert_rejected(response, Status::BadRequest, "CannotRemoveYourself").await;

        assert!(harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_ok());
        assert!(audit_entries(&harness, &server.id).await.is_empty());
    }

    // ---- the kick's order, pinned on its text (AFK S-3 D-2) ----------------

    /// `kick`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("member_remove.rs");
        let at = SOURCE
            .find("pub async fn kick(")
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

    /// AFK S-3 D-2: rank check, membership removed, then the eviction from
    /// every call in the server, each once, `?`-propagated, and the
    /// single-pointer removal gone. Mutations: the eviction moved above the
    /// membership removal; the eviction removed.
    #[test]
    fn the_kick_removes_the_membership_then_evicts() {
        const RANK: &str = "return Err(create_error!(NotElevated));";
        const REMOVE: &str = ".remove(db, &server, RemovalIntention::Kick, false) .await?;";
        const EVICT: &str =
            "remove_user_from_server_voice(db, voice_client, &server, member_id.id).await?;";

        let body = route_body();
        let mut last = 0;
        for needle in [RANK, REMOVE, EVICT] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the kick must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        for banned in [
            "get_user_voice_channel_in_server(",
            "remove_user_from_voice_channel(",
        ] {
            assert!(
                !body.contains(banned),
                "the kick must not call `{}`: {}",
                banned,
                body
            );
        }
    }

    /// The reason is validated before the rank check and the removal, and
    /// the `member_kick` entry is recorded after the removal and before the
    /// eviction, each once. Mutations: the validation moved below the
    /// removal; the record moved above the removal or below the eviction.
    #[test]
    fn the_kick_validates_the_reason_first_and_records_before_the_eviction() {
        const VALIDATE: &str = "let reason = reason.validated()?;";
        const RANK: &str = "return Err(create_error!(NotElevated));";
        const REMOVE: &str = ".remove(db, &server, RemovalIntention::Kick, false) .await?;";
        const RECORD: &str = "AuditLogEntry::record(";
        const EVICT: &str =
            "remove_user_from_server_voice(db, voice_client, &server, member_id.id).await?;";

        let body = route_body();
        let mut last = 0;
        for needle in [VALIDATE, RANK, REMOVE, RECORD, EVICT] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the kick must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        assert!(
            body.contains("action: AuditLogAction::MemberKick,"),
            "the kick records a member_kick: {}",
            body
        );
    }
}
