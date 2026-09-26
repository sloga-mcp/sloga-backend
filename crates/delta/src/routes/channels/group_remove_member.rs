use revolt_database::{
    util::reference::Reference,
    voice::{remove_user_from_voice_channel, UserVoiceChannel, VoiceClient},
    Channel, Database, User, AMQP,
};
use revolt_permissions::ChannelPermission;
use revolt_result::{create_error, Result, ToRevoltError};

use rocket::State;
use rocket_empty::EmptyResponse;

/// # Remove Member from Group
///
/// Removes a user from the group.
#[openapi(tag = "Groups")]
#[delete("/<group_id>/recipients/<member_id>")]
pub async fn remove_member(
    db: &State<Database>,
    voice_client: &State<VoiceClient>,
    amqp: &State<AMQP>,
    user: User,
    group_id: Reference<'_>,
    member_id: Reference<'_>,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let channel = group_id.as_channel(db).await?;

    if let Channel::Group {
        owner, recipients, ..
    } = &channel
    {
        if &user.id != owner {
            return Err(create_error!(MissingPermission {
                permission: ChannelPermission::ManageChannel.to_string()
            }));
        }

        let member = member_id.as_user(db).await?;
        if user.id == member.id {
            return Err(create_error!(CannotRemoveYourself));
        }

        if !recipients.contains(&member.id) {
            return Err(create_error!(NotInGroup));
        }

        channel
            .remove_user_from_group(db, amqp, &member, Some(&user.id), false)
            .await?;
    } else {
        return Err(create_error!(InvalidOperation));
    };

    // The member is already out of the group, so a retried removal answers
    // NotInGroup and can never redo this eviction (AFK S-3 DS-1). A failed
    // eviction is therefore reported (ERROR + Sentry) and the removal still
    // answers success.
    //
    // No Redis-only pre-check in front of it: `is_in_voice_channel` reads
    // only the user's channel set, so it skipped a connection the SFU has
    // and Redis does not. The helper decides for itself whether the user is
    // here at all (the SFU listing, the connection records, the voice state)
    // and runs nothing when they are not.
    let user_voice_channel = UserVoiceChannel::from_channel(&channel);
    if let Err(error) =
        remove_user_from_voice_channel(db, voice_client, &user_voice_channel, member_id.id).await
    {
        log::warn!(
            "{} was removed from group {}, but evicting them from its call failed: {error:?}",
            member_id.id,
            user_voice_channel.id
        );
        let _ = Err::<(), _>(error).to_internal_error();
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{events::client::EventV1, Channel, RelationshipStatus};
    use revolt_models::v0;
    use rocket::http::{Header, Status};

    #[test]
    fn success_remove_member() {
        crate::util::test::rt().block_on(success_remove_member_case())
    }

    async fn success_remove_member_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, mut user) = harness.new_user().await;
        let (_, _, mut other_user) = harness.new_user().await;

        #[allow(clippy::disallowed_methods)]
        user.apply_relationship(
            &harness.db,
            &mut other_user,
            RelationshipStatus::Friend,
            RelationshipStatus::Friend,
            None,
        )
        .await
        .unwrap();

        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                ..Default::default()
            },
            user.id.to_string(),
        )
        .await
        .unwrap();

        let response = harness
            .client
            .put(format!(
                "/channels/{}/recipients/{}",
                group.id(),
                other_user.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        harness
            .wait_for_event(&format!("{}!", other_user.id), |event| match event {
                EventV1::ChannelCreate(channel) => channel.id() == group.id(),
                _ => false,
            })
            .await;

        let event = harness
            .wait_for_event(group.id(), |event| match event {
                EventV1::ChannelGroupJoin { id, .. } => id == group.id(),
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelGroupJoin { user, .. } => assert_eq!(user, other_user.id),
            _ => unreachable!(),
        };

        let message = harness.wait_for_message(group.id()).await;

        assert_eq!(
            message.system,
            Some(v0::SystemMessage::UserAdded {
                id: other_user.id.to_string(),
                by: user.id.to_string()
            })
        );
    }

    #[test]
    fn fail_not_in_group() {
        crate::util::test::rt().block_on(fail_not_in_group_case())
    }

    async fn fail_not_in_group_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, _, other_user) = harness.new_user().await;

        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                ..Default::default()
            },
            user.id.to_string(),
        )
        .await
        .unwrap();

        let response = harness
            .client
            .delete(format!(
                "/channels/{}/recipients/{}",
                group.id(),
                other_user.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        dbg!(response.into_string().await);
        // FIXME: finish impl
        // assert_eq!(response.status(), Status::NotFound);
    }

    #[test]
    fn fail_not_group_owner() {
        crate::util::test::rt().block_on(fail_not_group_owner_case())
    }

    async fn fail_not_group_owner_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (_, session, other_user) = harness.new_user().await;
        let (_, _, user_to_be_kicked) = harness.new_user().await;

        let group = Channel::create_group(
            &harness.db,
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                users: vec![&other_user.id, &user_to_be_kicked.id]
                    .into_iter()
                    .cloned()
                    .collect(),
                ..Default::default()
            },
            user.id.to_string(),
        )
        .await
        .unwrap();

        let _response = harness
            .client
            .delete(format!(
                "/channels/{}/recipients/{}",
                group.id(),
                user_to_be_kicked.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        // FIXME: impl assert_eq!(response.status(), Status::Forbidden);
    }

    // ---- the eviction after the removal (AFK S-3 DS-1) ---------------------
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
            v0::DataCreateGroup {
                name: TestHarness::rand_string(),
                users: vec![member.id.clone()].into_iter().collect(),
                ..Default::default()
            },
            owner.id.to_string(),
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
    fn a_failed_eviction_still_removes_the_member() {
        crate::util::test::rt().block_on(a_failed_eviction_still_removes_the_member_case())
    }

    /// DS-1: the member is in the group call and the eviction fails
    /// (ABSENT_NODE, UnknownNode before any network). The removal is already
    /// durable and a retry would answer NotInGroup, so the route answers
    /// success, and the failed eviction tore nothing down. Mutation: the
    /// eviction error propagated (a non-2xx).
    async fn a_failed_eviction_still_removes_the_member_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, _, target) = harness.new_user().await;
        let group = group_with(&harness, &owner, &target).await;
        let uvc = UserVoiceChannel::from_channel(&group);
        join_recorded(&uvc, &target.id, "PA_group_live", &target.id).await;
        set_channel_node(group.id(), ABSENT_NODE)
            .await
            .expect("node");

        let response = harness
            .client
            .delete(format!("/channels/{}/recipients/{}", group.id(), target.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        delete_channel_node(group.id()).await.expect("unpin");

        assert_eq!(
            status,
            Status::NoContent,
            "a failed eviction after the removal must answer success: {}",
            body
        );
        assert!(
            !is_recipient(&harness, group.id(), &target.id).await,
            "the member is removed"
        );
        assert_eq!(
            voice_traces(&uvc, &target.id).await,
            (1, true, true, true),
            "a failed eviction tears nothing down"
        );

        delete_channel_voice_state(&uvc, &[target.id.clone()])
            .await
            .expect("cleanup");
    }

    #[test]
    fn a_removed_members_record_only_ghost_is_torn_down() {
        crate::util::test::rt().block_on(a_removed_members_record_only_ghost_is_torn_down_case())
    }

    /// A call that ended without its webhooks (no node pinned) left a
    /// connection record of the member and no other voice state, so the
    /// user's channel set does not name the group. The removal still tears
    /// the record down: the helper, not a Redis-only pre-check, decides
    /// whether the user is here. Mutations: the eviction removed; the
    /// `is_in_voice_channel` pre-check reinstated (it skips this user).
    async fn a_removed_members_record_only_ghost_is_torn_down_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, _, target) = harness.new_user().await;
        let group = group_with(&harness, &owner, &target).await;
        let uvc = UserVoiceChannel::from_channel(&group);
        assert!(
            record_voice_connection(&uvc, &target.id, "PA_group_ghost", &target.id)
                .await
                .expect("record")
        );
        assert_eq!(
            voice_traces(&uvc, &target.id).await,
            (1, false, false, false),
            "the ghost is a record and nothing else"
        );

        let response = harness
            .client
            .delete(format!("/channels/{}/recipients/{}", group.id(), target.id))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        assert!(!is_recipient(&harness, group.id(), &target.id).await);
        assert_eq!(
            voice_traces(&uvc, &target.id).await,
            (0, false, false, false),
            "the removed member's ghost must be torn down"
        );
    }

    // ---- the route's text (AFK S-3 DS-1) -----------------------------------

    /// `remove_member`'s body, comment lines dropped, whitespace collapsed,
    /// and the spaces rustfmt puts inside a wrapped call and before `.await`
    /// removed.
    fn route_body() -> String {
        const SOURCE: &str = include_str!("group_remove_member.rs");
        let at = SOURCE
            .find("pub async fn remove_member(")
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

    /// DS-1: the eviction runs AFTER the durable removal, its error is
    /// neither propagated nor silently dropped but reported through
    /// `to_internal_error()`, and no Redis-only pre-check stands in front of
    /// it. Mutations: the error propagated; the eviction removed; the
    /// pre-check reinstated.
    #[test]
    fn the_removal_evicts_after_it_is_durable_and_reports_a_failure() {
        const DURABLE: &str =
            ".remove_user_from_group(db, amqp, &member, Some(&user.id), false).await?;";
        const EVICT: &str = "if let Err(error) = remove_user_from_voice_channel(db, voice_client, \
             &user_voice_channel, member_id.id).await \u{7b}";
        const REPORT: &str = "let _ = Err::<(), _>(error).to_internal_error();";

        let body = route_body();
        let mut last = 0;
        for needle in [DURABLE, EVICT, REPORT] {
            assert_eq!(
                body.matches(needle).count(),
                1,
                "the removal must carry `{needle}` exactly once: {body}"
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
        for banned in [
            "is_in_voice_channel(",
            "let _ = remove_user_from_voice_channel",
            ".ok()",
            "to_internal_error()?",
        ] {
            assert!(
                !body.contains(banned),
                "the removal must not carry `{}`: {}",
                banned,
                body
            );
        }
    }
}
