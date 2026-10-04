use revolt_database::{
    util::{acker, permissions::DatabasePermissionQuery, reference::Reference},
    Database, User, AMQP,
};
use revolt_permissions::PermissionQuery;
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Mark Server As Read
///
/// Mark all channels in a server as read.
#[openapi(tag = "Server Information")]
#[put("/<target>/ack")]
pub async fn ack(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
) -> Result<EmptyResponse> {
    if user.bot.is_some() {
        return Err(create_error!(IsBot));
    }

    let server = target.as_server(db).await?;
    let mut query = DatabasePermissionQuery::new(db, &user).server(&server);
    if !query.are_we_a_member().await {
        return Err(create_error!(NotFound));
    }

    acker::ack_server(&user, &server, db, amqp).await?;
    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{events::client::EventV1, Channel, Member, PartialChannel, Server};
    use revolt_models::v0;
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};

    // ---- threads and forum posts (needs RabbitMQ and Redis) ----------------
    //
    // Threads and forum posts are never listed in `server.channels`, so a
    // server-wide mark-as-read that only walked that list left every one of
    // them unread. Each ack the route makes is published as a `ChannelAck` on
    // the user's private topic, which is what this test watches.
    //
    // The member never sends a message here. Sending acks the author, and
    // that `ChannelAck` would sit in the event buffer, where `wait_for_event`
    // also looks, and could pass the checks below with the route doing
    // nothing.

    /// Publish a marker `ChannelAck` on `marker_user`'s private topic and wait
    /// for it. The harness reads every topic through one `psubscribe("*")`
    /// connection and redis pub/sub is FIFO on it, so once the marker is seen,
    /// everything published before it is in the event buffer, where
    /// `assert_no_buffered_event` can see it. A copy of the helper in
    /// `channels/message_send.rs`, which is private to that module.
    async fn flush_with_marker(
        harness: &mut TestHarness,
        marker_user: &str,
        channel_id: &str,
    ) -> String {
        let marker = ulid::Ulid::new().to_string();

        EventV1::ChannelAck {
            id: channel_id.to_string(),
            user: marker_user.to_string(),
            message_id: marker.clone(),
        }
        .private(marker_user.to_string())
        .await;

        harness
            .wait_for_event(&format!("{marker_user}!"), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;

        marker
    }

    /// Any `ChannelAck` for `channel_id`.
    fn is_ack_for(event: &EventV1, channel_id: &str) -> bool {
        matches!(event, EventV1::ChannelAck { id, .. } if id == channel_id)
    }

    async fn server_channel(
        harness: &TestHarness,
        server: &mut Server,
        channel_type: v0::LegacyServerChannelType,
        name: &str,
    ) -> Channel {
        Channel::create_server_channel(
            &harness.db,
            server,
            v0::DataCreateServerChannel {
                channel_type,
                name: name.to_string(),
                ..Default::default()
            },
            true,
        )
        .await
        .expect("server channel")
    }

    #[test]
    fn server_ack_acks_joined_threads_and_posts_the_member_can_see() {
        crate::util::test::rt()
            .block_on(server_ack_acks_joined_threads_and_posts_the_member_can_see_case())
    }

    /// A member marks the server read. The thread they opened under a visible
    /// text channel and the post they opened in a forum are acked at their
    /// newest message. A thread they joined under a channel they cannot see
    /// is not, and no ack for it reaches them. Mutations: the acker from
    /// before thread acks (the wait for the thread times out), and the acker
    /// taking threads from every channel in the server with no visibility
    /// re-check (the hidden thread's ack is found in the buffer).
    async fn server_ack_acks_joined_threads_and_posts_the_member_can_see_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;
        let (mut server, _) = harness.new_server(&owner).await;
        Member::create(&harness.db, &server, &member, None)
            .await
            .expect("member");

        // `&mut server` for every create: a create from a stale copy would
        // write the server's channel list without the channels made before it.
        let visible = server_channel(
            &harness,
            &mut server,
            v0::LegacyServerChannelType::Text,
            "ack-visible",
        )
        .await;
        let mut hidden = server_channel(
            &harness,
            &mut server,
            v0::LegacyServerChannelType::Text,
            "ack-hidden",
        )
        .await;
        let forum = server_channel(
            &harness,
            &mut server,
            v0::LegacyServerChannelType::Forum,
            "ack-forum",
        )
        .await;

        // Nobody but the owner can see the hidden channel.
        hidden
            .update(
                &harness.db,
                PartialChannel {
                    default_permissions: Some(OverrideField {
                        a: 0,
                        d: ChannelPermission::ViewChannel as i64,
                    }),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("hide the channel");

        // The member opens the thread and the post, which joins them to both.
        // Neither path sends a message as the member: `create_thread` posts a
        // system message into the parent, and a post's starter message is the
        // route's job, not the model's.
        let thread = Channel::create_thread(
            &harness.db,
            &visible,
            &member,
            None,
            v0::DataCreateThread {
                name: "ack-thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("thread");
        let post = Channel::create_forum_post(
            &harness.db,
            &forum,
            &member,
            "ack-post".to_string(),
            vec![],
            None,
        )
        .await
        .expect("post");

        // The owner opens a thread under the hidden channel, and the member
        // is joined to it anyway.
        let hidden_thread = Channel::create_thread(
            &harness.db,
            &hidden,
            &owner,
            None,
            v0::DataCreateThread {
                name: "ack-hidden-thread".to_string(),
                auto_archive_minutes: None,
            },
        )
        .await
        .expect("hidden thread");
        harness
            .db
            .join_thread_if_absent(hidden_thread.id(), &member.id)
            .await
            .expect("join the hidden thread");

        // Each thread's newest message, minted after everything above so no
        // earlier event can carry it. Set directly: the debounced worker that
        // normally writes it runs seconds later.
        let thread_message = ulid::Ulid::new().to_string();
        let post_message = ulid::Ulid::new().to_string();
        let hidden_message = ulid::Ulid::new().to_string();
        for (channel, message) in [
            (&thread, &thread_message),
            (&post, &post_message),
            (&hidden_thread, &hidden_message),
        ] {
            assert!(
                harness
                    .db
                    .set_last_message_id_if_newer(channel.id(), message, false)
                    .await
                    .expect("last_message_id"),
                "the newest message of {} must be set",
                channel.id()
            );
        }

        // Nothing acked the thread or the post before the route ran. The
        // marker names the visible channel, so it matches neither check.
        let topic = format!("{}!", member.id);
        flush_with_marker(&mut harness, &member.id, visible.id()).await;
        harness.assert_no_buffered_event(&topic, |event| is_ack_for(event, thread.id()));
        harness.assert_no_buffered_event(&topic, |event| is_ack_for(event, post.id()));

        let response = harness
            .client
            .put(format!("/servers/{}/ack", server.id))
            .header(Header::new(
                "x-session-token",
                member_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        // Times out (and fails) after 30s if the route skipped either one.
        for (channel, message) in [(&thread, &thread_message), (&post, &post_message)] {
            harness
                .wait_for_event(&topic, |event| match event {
                    EventV1::ChannelAck { id, message_id, .. } => {
                        id == channel.id() && message_id == message
                    }
                    _ => false,
                })
                .await;
        }

        // Everything the route published is in the buffer once the marker
        // is seen, and none of it names the hidden thread.
        flush_with_marker(&mut harness, &member.id, visible.id()).await;
        harness.assert_no_buffered_event(&topic, |event| is_ack_for(event, hidden_thread.id()));
    }
}
