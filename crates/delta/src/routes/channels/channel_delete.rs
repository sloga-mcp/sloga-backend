use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    voice::{delete_voice_channel, remove_user_from_voice_channel, UserVoiceChannel, VoiceClient},
    Channel, Database, PartialChannel, User, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result, ToRevoltError};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Close Channel
///
/// Deletes a server channel, leaves a group or closes a group.
#[openapi(tag = "Channel Information")]
#[delete("/<target>?<options..>")]
pub async fn delete(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    options: v0::OptionsChannelDelete,
) -> Result<EmptyResponse> {
    let mut channel = target.as_channel(db).await?;

    // Threads delegate their permission calculus to the parent text channel;
    // resolve it BEFORE constructing the query.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;

    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    #[allow(deprecated)]
    match &channel {
        Channel::SavedMessages { .. } => Err(create_error!(NoEffect))?,
        Channel::DirectMessage { .. } => {
            channel
                .update(
                    db,
                    PartialChannel {
                        active: Some(false),
                        ..Default::default()
                    },
                    vec![],
                )
                .await?
        }
        Channel::Group { .. } => {
            channel
                .remove_user_from_group(
                    db,
                    amqp,
                    &user,
                    None,
                    options.leave_silently.unwrap_or_default(),
                )
                .await?;

            // The user has already left the group, so a retried leave cannot
            // redo this eviction (AFK S-3 DS-1). A failed eviction is
            // therefore reported (ERROR + Sentry) and the leave still
            // answers success.
            //
            // No Redis-only pre-check in front of it: `is_in_voice_channel`
            // reads only the user's channel set, so it skipped a connection
            // the SFU has and Redis does not. The helper decides for itself
            // whether the user is here at all (the SFU listing, the
            // connection records, the voice state) and runs nothing when they
            // are not.
            let user_voice_channel = UserVoiceChannel::from_channel(&channel);
            if let Err(error) =
                remove_user_from_voice_channel(db, voice_client, &user_voice_channel, &user.id)
                    .await
            {
                log::warn!(
                    "{} left group {}, but evicting them from its call failed: {error:?}",
                    user.id,
                    user_voice_channel.id
                );
                let _ = Err::<(), _>(error).to_internal_error();
            }
        }
        Channel::TextChannel { .. } => {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
            channel.delete(db).await?;

            delete_voice_channel(db, voice_client, &UserVoiceChannel::from_channel(&channel)).await?;
        }
        Channel::Forum { .. } => {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
            channel.delete(db).await?;
        }
        Channel::Thread { .. } => {
            // ManageChannel on the PARENT channel is required to delete a thread.
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageChannel)?;
            channel.delete(db).await?;
        }
    };

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{events::client::EventV1, Channel};
    use revolt_models::v0::DataCreateGroup;
    use rocket::http::{Header, Status};

    #[test]
    fn success_delete_group() {
        crate::util::test::rt().block_on(success_delete_group_case())
    }

    async fn success_delete_group_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let group = Channel::create_group(
            &harness.db,
            DataCreateGroup {
                ..Default::default()
            },
            user.id.clone(),
        )
        .await
        .expect("`Channel`");

        let response = harness
            .client
            .delete(format!("/channels/{}", group.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        harness
            .wait_for_event(group.id(), |event| match event {
                EventV1::ChannelDelete { id, .. } => id == group.id(),
                _ => false,
            })
            .await;
    }

    // TEST: member leaves group (no delete)
    // TEST: no effect with saved messages
    // TEST: DM set to inactive

    #[test]
    fn success_delete_channel() {
        crate::util::test::rt().block_on(success_delete_channel_case())
    }

    async fn success_delete_channel_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, channels) = harness.new_server(&user).await;
        let response = TestHarness::with_session(
            session,
            harness
                .client
                .delete(format!("/channels/{}", channels[0].id())),
        )
        .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);
        harness
            .wait_for_event(channels[0].id(), |event| match event {
                EventV1::ChannelDelete { id, .. } => id == channels[0].id(),
                _ => false,
            })
            .await;
    }

    // ---- the eviction after a group leave (AFK S-3 DS-1) -------------------
    //
    // Needs RabbitMQ and Redis, as every route test here does.

    use iso8601_timestamp::Timestamp;
    use revolt_database::{
        voice::{
            create_voice_state, delete_channel_node, delete_channel_voice_state,
            get_user_voice_channel_in_server, get_voice_channel_members, is_in_voice_channel,
            record_voice_connection, recorded_voice_connections, set_channel_node,
            UserVoiceChannel,
        },
        User,
    };

    /// A node name deliberately absent from `Revolt.toml`: an eviction
    /// addressed to it fails with `UnknownNode` before any network.
    const ABSENT_NODE: &str = "test-node-with-no-sfu";

    /// A group owned by `owner` with `member` in it.
    async fn group_with(harness: &TestHarness, owner: &User, member: &User) -> Channel {
        Channel::create_group(
            &harness.db,
            DataCreateGroup {
                users: vec![member.id.clone()].into_iter().collect(),
                ..Default::default()
            },
            owner.id.clone(),
        )
        .await
        .expect("group")
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

    /// What is left of `user_id` in `uvc`: the number of recorded
    /// connections, then whether it is in the user's channel set, in the
    /// channel's member set, and named by the per-group pointer.
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
        let parent = uvc.server_id.as_deref().unwrap_or(&uvc.id);
        let pointer = get_user_voice_channel_in_server(user_id, parent)
            .await
            .expect("pointer read")
            .as_deref()
            == Some(uvc.id.as_str());
        (recorded, listed, member, pointer)
    }

    async fn is_recipient(harness: &TestHarness, group_id: &str, user_id: &str) -> bool {
        match harness.db.fetch_channel(group_id).await.expect("group") {
            Channel::Group { recipients, .. } => recipients.iter().any(|id| id == user_id),
            _ => unreachable!("a group"),
        }
    }

    #[test]
    fn a_failed_eviction_still_leaves_the_group() {
        crate::util::test::rt().block_on(a_failed_eviction_still_leaves_the_group_case())
    }

    /// DS-1: a member in the group call leaves and the eviction fails
    /// (ABSENT_NODE, UnknownNode before any network). The leave is already
    /// durable and cannot be retried, so the route answers success, and the
    /// failed eviction tore nothing down. Mutation: the eviction error
    /// propagated (a non-2xx).
    async fn a_failed_eviction_still_leaves_the_group_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, leaver) = harness.new_user().await;
        let group = group_with(&harness, &owner, &leaver).await;
        let uvc = UserVoiceChannel::from_channel(&group);
        join_recorded(&uvc, &leaver.id, "PA_leave_live", &leaver.id).await;
        set_channel_node(group.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = harness
            .client
            .delete(format!("/channels/{}", group.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        delete_channel_node(group.id()).await.expect("unpin");

        assert_eq!(
            status,
            Status::NoContent,
            "a failed eviction after the leave must answer success: {}",
            body
        );
        assert!(
            !is_recipient(&harness, group.id(), &leaver.id).await,
            "the user has left"
        );
        assert_eq!(
            voice_traces(&uvc, &leaver.id).await,
            (1, true, true, true),
            "a failed eviction tears nothing down"
        );

        delete_channel_voice_state(&uvc, &[leaver.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn a_leavers_record_only_ghost_is_torn_down() {
        crate::util::test::rt().block_on(a_leavers_record_only_ghost_is_torn_down_case())
    }

    /// A call that ended without its webhooks (no node pinned) left a
    /// connection record of the leaver and no other voice state, so the
    /// user's channel set does not name the group. The leave still tears the
    /// record down: the helper, not a Redis-only pre-check, decides whether
    /// the user is here. Mutations: the eviction removed; the
    /// `is_in_voice_channel` pre-check reinstated (it skips this user).
    async fn a_leavers_record_only_ghost_is_torn_down_case() {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, session, leaver) = harness.new_user().await;
        let group = group_with(&harness, &owner, &leaver).await;
        let uvc = UserVoiceChannel::from_channel(&group);
        assert!(
            record_voice_connection(&uvc, &leaver.id, "PA_leave_ghost", &leaver.id)
                .await
                .expect("record")
        );
        assert_eq!(
            voice_traces(&uvc, &leaver.id).await,
            (1, false, false, false),
            "the ghost is a record and nothing else"
        );

        let response = harness
            .client
            .delete(format!("/channels/{}", group.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        assert!(!is_recipient(&harness, group.id(), &leaver.id).await);
        assert_eq!(
            voice_traces(&uvc, &leaver.id).await,
            (0, false, false, false),
            "the leaver's ghost must be torn down"
        );
    }

    // ---- the route's text (AFK S-3 DS-1) -----------------------------------

    /// `delete`'s body, comment lines dropped, whitespace collapsed, and the
    /// spaces rustfmt puts inside a wrapped call and before `.await` removed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("channel_delete.rs");
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
            .replace("( ", "(")
            .replace(" )", ")")
            .replace(",)", ")")
            .replace(" .await", ".await")
    }

    /// DS-1: in the group arm, the eviction runs AFTER the durable leave,
    /// its error is neither propagated nor silently dropped but reported
    /// through `to_internal_error()`, and no Redis-only pre-check stands in
    /// front of it. The server-channel arm keeps its own teardown.
    /// Mutations: the error propagated; the eviction removed; the pre-check
    /// reinstated.
    #[test]
    fn a_group_leave_evicts_after_it_is_durable_and_reports_a_failure() {
        const GROUP_ARM: &str = "Channel::Group \u{7b} .. \u{7d} =>";
        const DURABLE: &str = ".remove_user_from_group(db, amqp, &user, None, \
             options.leave_silently.unwrap_or_default()).await?;";
        const EVICT: &str = "if let Err(error) = remove_user_from_voice_channel(db, voice_client, \
             &user_voice_channel, &user.id).await \u{7b}";
        const REPORT: &str = "let _ = Err::<(), _>(error).to_internal_error();";
        const NEXT_ARM: &str = "Channel::TextChannel \u{7b} .. \u{7d} =>";

        let body = route_body();
        let mut last = 0;
        for needle in [GROUP_ARM, DURABLE, EVICT, REPORT, NEXT_ARM] {
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
            body.matches("remove_user_from_voice_channel(").count(),
            1,
            "one eviction, the one pinned above: {body}"
        );
        assert!(
            body.contains(
                "delete_voice_channel(db, voice_client, &UserVoiceChannel::from_channel(&channel)).await?;"
            ),
            "the server-channel teardown is out of scope and unchanged: {}",
            body
        );
        for banned in [
            "is_in_voice_channel(",
            "let _ = remove_user_from_voice_channel",
            ".ok()",
            "to_internal_error()?",
        ] {
            assert!(
                !body.contains(banned),
                "the route must not carry `{}`: {}",
                banned,
                body
            );
        }
    }
}
