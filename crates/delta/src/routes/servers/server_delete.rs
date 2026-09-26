use revolt_database::{
    util::reference::Reference,
    voice::{delete_voice_channel, remove_user_from_server_voice, UserVoiceChannel, VoiceClient},
    Database, RemovalIntention, User,
};
use revolt_models::v0;
use revolt_result::Result;
use rocket::State;

use rocket_empty::EmptyResponse;

/// # Delete / Leave Server
///
/// Deletes a server if owner otherwise leaves.
#[openapi(tag = "Server Information")]
#[delete("/<target>?<options..>")]
pub async fn delete(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    user: User,
    target: Reference<'_>,
    options: v0::OptionsServerDelete,
) -> Result<EmptyResponse> {
    let server = target.as_server(db).await?;
    let member = db.fetch_member(target.id, &user.id).await?;

    if server.owner == user.id {
        for channel_id in &server.channels {
            delete_voice_channel(
                db,
                voice_client,
                &UserVoiceChannel {
                    id: channel_id.clone(),
                    server_id: Some(server.id.clone()),
                },
            )
            .await?;
        }

        server.delete(db).await
    } else {
        // Every call in the server is reached, not only the one the
        // per-server pointer names (AFK S-3 F-3). The eviction runs BEFORE
        // the membership is removed: an eviction that fails answers an error
        // while the user is still a member, so leaving again retries it.
        remove_user_from_server_voice(db, voice_client, &server, &user.id).await?;

        member
            .remove(
                db,
                &server,
                RemovalIntention::Leave,
                options.leave_silently.unwrap_or_default(),
            )
            .await
    }
    .map(|_| EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            get_user_voice_channel_in_server, get_voice_channel_members, is_in_voice_channel,
            record_voice_connection, recorded_voice_connections, set_channel_node,
            UserVoiceChannel,
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

    async fn leave<'a>(
        harness: &'a TestHarness,
        token: &str,
        server_id: &str,
    ) -> rocket::local::asynchronous::LocalResponse<'a> {
        harness
            .client
            .delete(format!("/servers/{server_id}"))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn leaving_a_server_evicts_the_member() {
        crate::util::test::rt().block_on(leaving_a_server_evicts_the_member_case())
    }

    /// AFK S-3 F-3: a member leaving the server is torn down from its calls,
    /// here a ghost of an ended call with two recorded connections.
    /// Mutation: the eviction removed.
    async fn leaving_a_server_evicts_the_member_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // leaves
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Ended").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_leave_bare", &user_b.id).await;
        join_recorded(
            &uvc,
            &user_b.id,
            "PA_leave_device",
            &format!("{}:DEV", user_b.id),
        )
        .await;
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (2, true, true, true),
            "the ghost is in place"
        );

        let response = leave(&harness, &session_b.token, &server.id).await;
        assert_eq!(response.status(), Status::NoContent, "leaving succeeds");

        assert!(harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_err());
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (0, false, false, false),
            "the departed member's ghost must be torn down"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_leave_whose_eviction_fails_can_be_retried() {
        crate::util::test::rt().block_on(a_leave_whose_eviction_fails_can_be_retried_case())
    }

    /// AFK S-3 D-2: the eviction precedes the membership removal, so an
    /// eviction that fails (ABSENT_NODE, UnknownNode before any network)
    /// answers an error while the user is still a member, and tears nothing
    /// down. Leaving again, once the cause is gone, completes both.
    /// Mutation: the eviction moved below the membership removal.
    async fn a_leave_whose_eviction_fails_can_be_retried_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // leaves
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

        let response = leave(&harness, &session_b.token, &server.id).await;
        assert_eq!(response.status(), Status::BadRequest);
        let body = response.into_string().await.unwrap_or_default();
        assert!(body.contains("UnknownNode"), "{}", body);

        assert!(
            harness
                .db
                .fetch_member(&server.id, &user_b.id)
                .await
                .is_ok(),
            "a leave whose eviction failed keeps the member, so it can be retried"
        );
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (1, true, true, true),
            "a failed eviction tears nothing down"
        );

        // The call ended: the retry reaches the ghost with no SFU involved.
        delete_channel_node(channel.id()).await.expect("node gone");
        let response = leave(&harness, &session_b.token, &server.id).await;
        assert_eq!(response.status(), Status::NoContent, "the retry succeeds");
        assert!(harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_err());
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (0, false, false, false),
            "the retry tears the ghost down"
        );

        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");
    }

    // Compile-only without RabbitMQ and Redis: see the section note above.
    #[test]
    fn a_member_in_no_call_leaves_past_a_call_on_an_unlistable_node() {
        crate::util::test::rt()
            .block_on(a_member_in_no_call_leaves_past_a_call_on_an_unlistable_node_case())
    }

    /// AFK S-3 WB-2: a call the member was never in, pinned to a node that
    /// cannot be listed (ABSENT_NODE, UnknownNode before any network), does
    /// not fail their leave: they hold nothing there to tear down, so the
    /// failed eviction is reported and that call is skipped. Mutation: the
    /// eviction's error propagated whatever the member holds in the call
    /// (the WB-2 shape) answers 400 UnknownNode and keeps the member.
    async fn a_member_in_no_call_leaves_past_a_call_on_an_unlistable_node_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // leaves
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Elsewhere").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (0, false, false, false),
            "the member is in no call"
        );
        set_channel_node(channel.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = leave(&harness, &session_b.token, &server.id).await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let still_member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_ok();
        let traces = voice_traces(&uvc, &user_b.id).await;
        delete_channel_node(channel.id()).await.expect("cleanup");

        assert_eq!(
            status,
            Status::NoContent,
            "a call the member is not in must not fail the leave: {}",
            body
        );
        assert!(!still_member, "the member has left");
        assert_eq!(traces, (0, false, false, false), "nothing was written");
    }

    // ---- the leave's order, pinned on its text (AFK S-3 D-2) ---------------

    /// `delete`'s body, comment lines dropped and whitespace collapsed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("server_delete.rs");
        let at = SOURCE
            .find("pub async fn delete(")
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

    /// AFK S-3 D-2: in the leave branch (the one after the owner's
    /// `server.delete`), the eviction from every call in the server precedes
    /// the membership removal, once, `?`-propagated, and the single-pointer
    /// removal is gone. Mutations: the eviction moved below the membership
    /// removal; the eviction removed.
    #[test]
    fn a_leave_evicts_before_removing_the_membership() {
        const BRANCH: &str = "server.delete(db).await \u{7d} else \u{7b}";
        const EVICT: &str =
            "remove_user_from_server_voice(db, voice_client, &server, &user.id).await?;";
        const REMOVE: &str = "member .remove( db, &server, RemovalIntention::Leave,";

        let body = route_body();
        let mut last = 0;
        for needle in [BRANCH, EVICT, REMOVE] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the route must carry `{needle}` exactly once: {body}"
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
                "the route must not call `{}`: {}",
                banned,
                body
            );
        }
    }
}
