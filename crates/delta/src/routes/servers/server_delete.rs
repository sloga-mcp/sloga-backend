use revolt_database::{
    util::reference::Reference,
    voice::{delete_voice_channel, remove_user_from_server_voice, UserVoiceChannel, VoiceClient},
    Database, RemovalIntention, User,
};
use revolt_models::v0;
use revolt_result::{ErrorType, Result, ToRevoltError};
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
        // The membership is removed FIRST (AFK S-3 S6A-1), as a kick and a
        // ban do, so a rejoin racing the eviction below is refused by the
        // join-time Connect re-check (S-3 D-3), which also closes the
        // sibling-token window of WB-7.
        member
            .remove(
                db,
                &server,
                RemovalIntention::Leave,
                options.leave_silently.unwrap_or_default(),
            )
            .await?;

        // Every call in the server is reached, not only the one the
        // per-server pointer names (S-3 F-3). Leaving is the user's own
        // action and must not depend on an SFU: with the eviction first, a
        // user holding voice state on a node that cannot be reached (breaker
        // open, a pin naming a node missing from the config, a failed
        // listing) could never leave the server. The membership is gone and a
        // retried leave answers NotFound, so a failed eviction is reported
        // and the leave still answers success (decision DS-1), whatever the
        // failure (a connection the SFU listed and could not remove
        // included). Reported exactly once: an `InternalError` already went
        // through `to_internal_error()` (ERROR + Sentry) where it arose; any
        // other error (`UnknownNode`) was reported nowhere and goes through
        // it here.
        if let Err(error) = remove_user_from_server_voice(db, voice_client, &server, &user.id).await
        {
            log::warn!(
                "{} left server {}, but evicting them from its calls failed: {error:?}",
                user.id,
                server.id
            );
            if !matches!(error.error_type, ErrorType::InternalError) {
                let _ = Err::<(), _>(error).to_internal_error();
            }
        }

        Ok(())
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
    fn a_member_in_a_call_on_an_unreachable_node_still_leaves() {
        crate::util::test::rt()
            .block_on(a_member_in_a_call_on_an_unreachable_node_still_leaves_case())
    }

    /// AFK S-3 S6A-1: a member holding voice state in a call whose node
    /// cannot be reached (ABSENT_NODE, UnknownNode before any network) still
    /// leaves the server. The membership is removed first; the eviction that
    /// then fails is reported and discarded (DS-1), so the leave answers
    /// success, and the Connect re-check refuses any rejoin. Until S6A-1 the
    /// eviction ran first and its error was the answer: 400 UnknownNode with
    /// the member kept, and the same for as long as the node stayed
    /// unreachable. Mutation: the eviction's error propagated with `?`.
    async fn a_member_in_a_call_on_an_unreachable_node_still_leaves_case() {
        let harness = TestHarness::new().await;
        let (_a, _session_a, user_a) = harness.new_user().await; // owner
        let (_b, session_b, user_b) = harness.new_user().await; // leaves
        let (server, _channels) = harness.new_server(&user_a).await;
        Member::create(&harness.db, &server, &user_b, None)
            .await
            .expect("member");

        let channel = voice_channel(&harness, &server, "Live").await;
        let uvc = UserVoiceChannel::from_channel(&channel);
        join_recorded(&uvc, &user_b.id, "PA_unreachable", &user_b.id).await;
        set_channel_node(channel.id(), ABSENT_NODE)
            .await
            .expect("node");
        assert_eq!(
            voice_traces(&uvc, &user_b.id).await,
            (1, true, true, true),
            "the member holds voice state in the call"
        );

        let response = leave(&harness, &session_b.token, &server.id).await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        let still_member = harness
            .db
            .fetch_member(&server.id, &user_b.id)
            .await
            .is_ok();
        delete_channel_node(channel.id()).await.expect("cleanup");
        delete_channel_voice_state(&uvc, &[user_b.id.clone()])
            .await
            .expect("cleanup");

        assert_eq!(
            status,
            Status::NoContent,
            "an unreachable node must not stop a member leaving: {}",
            body
        );
        assert!(!still_member, "the member has left");
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
    /// failed eviction is reported and that call is skipped, and nothing is
    /// written. Since S6A-1 the leave discards ANY eviction error, so this
    /// route no longer sees the WB-2 mutation (the eviction's error
    /// propagated whatever the member holds in the call); that is pinned in
    /// `voice/mod.rs`, where the WB-2 split lives, and kick and ban still
    /// answer it.
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

    // ---- the leave's order, pinned on its text (AFK S-3 D-2, S6A-1) --------

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

    /// AFK S-3 S6A-1 (amending D-2 for the leave): in the leave branch (the
    /// one after the owner's `server.delete`), the membership removal,
    /// `?`-propagated, precedes the eviction from every call in the server,
    /// whose error is reported exactly once and discarded (DS-1), never
    /// propagated; and the single-pointer removal is gone. The report is
    /// pinned here because no route test observes it: an `InternalError` was
    /// already reported where it arose, anything else goes through
    /// `to_internal_error()` once. Mutations: the eviction moved back above
    /// the membership removal; its error propagated with `?`; the report
    /// dropped; the report made unconditional (an `InternalError` reported
    /// twice).
    #[test]
    fn a_leave_removes_the_membership_before_evicting() {
        const BRANCH: &str = "server.delete(db).await \u{7d} else \u{7b}";
        const REMOVE: &str = "member .remove( db, &server, RemovalIntention::Leave, \
                              options.leave_silently.unwrap_or_default(), ) .await?;";
        const EVICT: &str = "if let Err(error) = \
                             remove_user_from_server_voice(db, voice_client, &server, &user.id).await \
                             \u{7b}";
        const REPORT: &str = "if !matches!(error.error_type, ErrorType::InternalError) \u{7b} \
                              let _ = Err::<(), _>(error).to_internal_error(); \u{7d} \u{7d} \
                              Ok(()) \u{7d}";

        let body = route_body();
        let mut last = 0;
        for needle in [BRANCH, REMOVE, EVICT, REPORT] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the route must carry `{needle}` exactly once: {body}"
            );
            let at = body.find(needle).expect("counted above");
            assert!(last < at, "`{}` is out of order: {}", needle, body);
            last = at;
        }
        assert_eq!(
            body.matches("remove_user_from_server_voice(").count(),
            1,
            "the leave evicts once, and never with `?`: {body}"
        );
        assert_eq!(
            body.matches("to_internal_error()").count(),
            1,
            "a failed eviction is reported exactly once: {body}"
        );
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
