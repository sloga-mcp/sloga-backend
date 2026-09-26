use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{remove_user_from_server_voice, VoiceClient},
    Database, RemovalIntention, User,
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
) -> Result<EmptyResponse> {
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
        Channel, Member, Server,
    };
    use revolt_models::v0;
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

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
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
}
