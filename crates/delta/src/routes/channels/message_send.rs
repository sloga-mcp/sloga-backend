use std::time::Duration;

use revolt_database::events::client::EventV1;
use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::{
    util::idempotency::IdempotencyKey, util::reference::Reference, Database, User,
};
use revolt_database::{Channel, Interactions, Message, Referral, ReferralActivity, AMQP};
use revolt_models::v0;
use revolt_permissions::PermissionQuery;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::serde::json::Json;
use rocket::State;
use validator::Validate;

/// # Send Message
///
/// Sends a message to the given channel.
#[openapi(tag = "Messaging")]
#[post("/<target>/messages", data = "<data>")]
pub async fn message_send(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    data: Json<v0::DataMessageSend>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    // Ensure we have permissions to send a message
    let channel = target.as_channel(db).await?;

    // Forum channels have no message stream of their own — content lives in
    // posts (threads). Fail closed on direct sends.
    if matches!(channel, Channel::Forum { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    // Threads delegate their permission calculus to the parent text channel;
    // resolve it BEFORE constructing the query so a thread under a private
    // parent inherits the parent's overrides instead of falling through to
    // server-wide defaults.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    // Archived or locked threads reject new messages unless the sender can
    // manage the parent channel (which is also how a thread gets unarchived).
    crate::util::threads::ensure_thread_writable(&channel, &permissions)?;

    // Verify permissions for masquerade
    if let Some(masq) = &data.masquerade {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::Masquerade)?;

        if masq.colour.is_some() {
            permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageRole)?;
        }
    }

    // Check permissions for embeds
    if data.embeds.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::SendEmbeds)?;
    }

    // Check permissions for files
    if data.attachments.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::UploadFiles)?;
    }

    crate::util::slowmode::enforce_slowmode(&user, &channel, &permissions).await?;

    // Ensure interactions information is correct
    if let Some(interactions) = &data.interactions {
        let interactions: Interactions = interactions.clone().into();
        interactions.validate(db, &permissions).await?;
    }

    // Disallow mentions for new users (TRUST-0: <12 hours age) in public servers
    let allow_mentions = if let Some(server) = query.server_ref() {
        if server.discoverable {
            (ulid::Ulid::from_string(&user.id)
                .unwrap()
                .datetime()
                .elapsed()
                .expect("Time went backwards"))
                >= Duration::from_hours(12)
        } else {
            true
        }
    } else {
        true
    };

    // Create the message
    let author: v0::User = user.clone().into(db, Some(&user)).await;

    // Make sure we have server member (edge case if server owner)
    query.are_we_a_member().await;

    // Create model user / members
    let model_user = user
        .clone()
        .into_known_static(revolt_presence::is_online(&user.id).await)
        .await;

    let model_member: Option<v0::Member> = query
        .member_ref()
        .as_ref()
        .map(|member| member.clone().into_owned().into());

    // Capture the thread's identity before `channel` is consumed by the send,
    // so we can auto-join the author once the message lands.
    let thread_info = if let Channel::Thread { server, .. } = &channel {
        Some((channel.id().to_string(), server.clone()))
    } else {
        None
    };

    // Notes to self don't count towards a pending referral.
    let counts_for_referral = !matches!(channel, Channel::SavedMessages { .. });

    let message = Message::create_from_api(
        db,
        Some(amqp),
        channel,
        data,
        v0::MessageAuthor::User(&author),
        Some(model_user.clone()),
        model_member.clone(),
        user.limits().await,
        idempotency,
        permissions.has_channel_permission(ChannelPermission::SendEmbeds),
        allow_mentions,
    )
    .await?;

    // Recorded as soon as the message is stored, before the thread join
    // below can fail the request.
    if counts_for_referral {
        Referral::record_activity(db, &user, ReferralActivity::Message).await;
    }

    // Sending in a thread joins you to it (Discord parity), so you start
    // receiving its notifications.
    if let Some((thread_id, server_id)) = thread_info {
        if db.join_thread_if_absent(&thread_id, &user.id).await? {
            EventV1::ThreadMemberJoin {
                id: thread_id,
                user: user.id.clone(),
            }
            .p(server_id)
            .await;
        }
    }

    Ok(Json(message.into_model(Some(model_user), model_member)))
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{events::client::EventV1, Bot};
    use revolt_database::{
        util::{idempotency::IdempotencyKey, reference::Reference},
        Channel, Member, Message, MessageFlagsValue, PartialChannel, PartialMember, Role, Server,
    };
    use revolt_database::{PartialUser, Referral, ReferralSource};
    use revolt_models::v0::{self, DataCreateServerChannel, MessageFlags};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use revolt_result::ErrorType;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    #[test]
    fn message_mention_constraints() {
        crate::util::test::rt().block_on(message_mention_constraints_case())
    }

    async fn message_mention_constraints_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (_, _, second_user) = harness.new_user().await;

        let (server, channels) = Server::create(
            &harness.db,
            v0::DataCreateServer {
                name: "Test Server".to_string(),
                ..Default::default()
            },
            &user,
            true,
        )
        .await
        .expect("Failed to create test server");

        let server_mut: &mut Server = &mut server.clone();
        let mut locked_channel = Channel::create_server_channel(
            &harness.db,
            server_mut,
            DataCreateServerChannel {
                channel_type: v0::LegacyServerChannelType::Text,
                name: "Hidden Channel".to_string(),
                description: None,
                nsfw: Some(false),
                spoiler: None,
                voice: None,
                announcement: None,
            },
            true,
        )
        .await
        .expect("Failed to make new channel");

        let role = Role::create(&harness.db, &server, "Show Hidden Channel".to_string())
            .await
            .expect("Failed to create the role");

        let mut overrides = HashMap::new();
        overrides.insert(
            role.id.clone(),
            OverrideField {
                a: (ChannelPermission::ViewChannel) as i64,
                d: 0,
            },
        );

        let partial = PartialChannel {
            name: None,
            owner: None,
            description: None,
            icon: None,
            nsfw: None,
            spoiler: None,
            active: None,
            permissions: None,
            role_permissions: Some(overrides),
            default_permissions: Some(OverrideField {
                a: 0,
                d: ChannelPermission::ViewChannel as i64,
            }),
            last_message_id: None,
            voice: None,
            slowmode: None,
            archived: None,
            archived_timestamp: None,
            tags: None,
            require_tag: None,
            default_sort: None,
            force_sort: None,
            auto_archive_minutes: None,
            default_auto_archive_minutes: None,
            applied_tags: None,
            announcement: None,
        };
        locked_channel
            .update(&harness.db, partial, vec![])
            .await
            .expect("Failed to update the channel permissions for special role");

        Member::create(&harness.db, &server, &user, Some(channels.clone()))
            .await
            .expect("Failed to create member");
        let member = Reference::from_unchecked(&user.id)
            .as_member(&harness.db, &server.id)
            .await
            .expect("Failed to get member");

        // Second user is not part of the server
        let message = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            locked_channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("<@{}>", second_user.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("0".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message");

        // The mention should not go through here
        assert!(
            message.mentions.is_none() || message.mentions.unwrap().is_empty(),
            "Mention failed to be scrubbed when the user is not part of the server"
        );

        Member::create(&harness.db, &server, &second_user, Some(channels.clone()))
            .await
            .expect("Failed to create second member");
        let mut second_member = Reference::from_unchecked(&second_user.id)
            .as_member(&harness.db, &server.id)
            .await
            .expect("Failed to get second member");

        // Second user cannot see the channel
        let message = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            locked_channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("<@{}>", second_user.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message");

        // The mention should not go through here
        assert!(
            message.mentions.is_none() || message.mentions.unwrap().is_empty(),
            "Mention failed to be scrubbed when the user cannot see the channel"
        );

        let second_member_roles = vec![role.id.clone()];
        let partial = PartialMember {
            id: None,
            joined_at: None,
            nickname: None,
            pronouns: None,
            avatar: None,
            timeout: None,
            roles: Some(second_member_roles),
            can_publish: None,
            can_receive: None,
        };
        second_member
            .update(&harness.db, partial, vec![])
            .await
            .expect("Failed to update the second user's roles");

        // This time the mention SHOULD go through
        let message = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            locked_channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("<@{}>", second_user.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("2".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message");

        // The mention SHOULD go through here
        assert!(
            message.mentions.is_some() && !message.mentions.unwrap().is_empty(),
            "Mention was scrubbed when the user can see the channel"
        );
    }

    #[test]
    fn message_reply() {
        crate::util::test::rt().block_on(message_reply_case())
    }

    async fn message_reply_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let (_, member, message) = harness.new_message(&user, &server, channels).await;

        // Send a message with a reply
        // Should succeed
        let message_with_reply = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: Some(true),
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            false,
        )
        .await
        .expect("Failed to create message with reply");

        assert!(
            message_with_reply.replies.is_some(),
            "Message replies is None",
        );

        let replies = message_with_reply.replies.unwrap();

        assert!(!replies.is_empty(), "Message replies is empty",);

        assert_eq!(replies[0], message.id, "Message reply ID does not match",);

        // Delete the message
        message
            .clone()
            .delete(&harness.db)
            .await
            .expect("Failed to delete message");

        // Attempt to create messages with a reply to a deleted message

        // fail_if_not_exists is set to false
        // Should send the message without a reply
        let message_with_missing_reply = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with missing reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: Some(false),
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("3".to_string()),
            false,
            false,
        )
        .await
        .expect("Failed to create message with missing reply");

        assert!(
            message_with_missing_reply.replies.is_none()
                || message_with_missing_reply.replies.unwrap().is_empty(),
            "Message replies exist when they shouldn't",
        );

        // fail_if_not_exists is set to true
        // Should fail to send the message
        Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with missing reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: Some(true),
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("4".to_string()),
            false,
            false,
        )
        .await
        .expect_err("Created message with missing reply and true fail");

        // fail_if_not_exists is not set
        // Should fail to send the message
        Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Message with missing reply".to_string()),
                nonce: None,
                attachments: None,
                replies: Some(vec![v0::ReplyIntent {
                    id: message.id.clone(),
                    mention: false,
                    fail_if_not_exists: None,
                }]),
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.clone().into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("4".to_string()),
            false,
            false,
        )
        .await
        .expect_err("Created message with missing reply and none fail");
    }

    #[test]
    fn mass_mentions_test() {
        crate::util::test::rt().block_on(mass_mentions_test_case())
    }

    async fn mass_mentions_test_case() {
        let harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (_, _, other_user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let role = harness
            .new_role(
                &server,
                1,
                Some(OverrideField {
                    a: (ChannelPermission::MentionEveryone as i64)
                        | (ChannelPermission::MentionRoles as i64),
                    d: 0,
                }),
            )
            .await;
        let (mut other_member, _) = Member::create(&harness.db, &server, &other_user, None)
            .await
            .expect("Failed to add test member");

        // Send a message with an everyone and role mention.
        // Should fail
        let bad_message_with_mentions = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("Mentioning @everyone and role <%{}>", &role.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(
                &other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(
                other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(other_member.clone().into()),
            other_user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect_err("Should not have created message with everyone and role pings");

        assert!(
            matches!(
                bad_message_with_mentions.error_type,
                ErrorType::MissingPermission { .. }
            ),
            "Intentional permissions error did not return MissingPermission"
        );

        // Send a mass mention inside a codeblock.
        // Should be undetected and therefor pass
        let message_with_codeblock = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("Mentioning `@everyone` and role `<%{}>`", &role.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(
                &other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(
                other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(other_member.clone().into()),
            other_user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message with everyone and role pings in codeblocks");

        assert!(
            message_with_codeblock.flags.is_none()
                || !MessageFlagsValue(message_with_codeblock.flags.unwrap())
                    .has(MessageFlags::MentionsEveryone),
            "Message flags mentions everyone when inside codeblock",
        );

        assert!(
            message_with_codeblock.role_mentions.is_none(),
            "Role mentions detected when inside codeblock"
        );

        other_member.roles.push(role.id.clone());
        harness
            .db
            .update_member(
                &other_member.id,
                &PartialMember {
                    avatar: None,
                    id: None,
                    joined_at: None,
                    nickname: None,
                    pronouns: None,
                    roles: Some(vec![role.id.clone()]),
                    timeout: None,
                    can_publish: None,
                    can_receive: None,
                },
                vec![],
            )
            .await
            .expect("Failed to add role to user");

        // Send a message with an everyone and role mention.
        // Should succeed
        let message_with_mentions = Message::create_from_api(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            v0::DataMessageSend {
                content: Some(format!("Mentioning @everyone and role <%{}>", &role.id)),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            v0::MessageAuthor::User(
                &other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(
                other_user
                    .clone()
                    .into(&harness.db, Some(&other_user))
                    .await,
            ),
            Some(other_member.clone().into()),
            other_user.limits().await,
            IdempotencyKey::unchecked_from_string("1".to_string()),
            false,
            true,
        )
        .await
        .expect("Failed to create message with everyone and role pings");

        assert!(
            message_with_mentions.flags.is_some(),
            "Message flags is None",
        );

        assert!(
            MessageFlagsValue(message_with_mentions.flags.unwrap())
                .has(MessageFlags::MentionsEveryone),
            "Message flags does not mention everyone. Flag value is {}",
            message_with_mentions.flags.unwrap()
        );

        assert!(
            message_with_mentions.role_mentions.is_some(),
            "Message has no role mentions"
        );
    }

    // Self-ack: sending marks the channel read for a human author.
    //
    // The negative tests below all pass `Some(&harness.amqp)`: the self-ack is
    // gated on `amqp` being present, so `None` would pass them vacuously.

    /// Publish a marker `ChannelAck` on `marker_user`'s private topic and wait
    /// for it. The harness reads every topic through one `psubscribe("*")`
    /// connection and redis pub/sub is FIFO on it, so once the marker is seen,
    /// everything the send published before it (the `Message` fan-out and any
    /// self-ack, both awaited inside `send`) is in the event buffer, where
    /// `assert_no_buffered_event` can see it. Returns the marker's id.
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

    /// The send's own `Message` event reached the harness, so its publishes
    /// were observable in this run. Served from the buffer after the marker.
    async fn assert_fanned_out(harness: &mut TestHarness, channel_id: &str, message_id: &str) {
        harness
            .wait_for_event(channel_id, |event| match event {
                EventV1::Message(message) => message.id == message_id,
                _ => false,
            })
            .await;
    }

    /// Any `ChannelAck` other than the marker.
    fn is_stray_ack(event: &EventV1, marker: &str) -> bool {
        match event {
            EventV1::ChannelAck { message_id, .. } => message_id.as_str() != marker,
            _ => false,
        }
    }

    fn plain_send(content: &str) -> v0::DataMessageSend {
        v0::DataMessageSend {
            content: Some(content.to_string()),
            nonce: None,
            attachments: None,
            replies: None,
            embeds: None,
            masquerade: None,
            interactions: None,
            components: None,
            sticker_ids: None,
            flags: None,
        }
    }

    /// A human author is acked on both send paths: the route
    /// (`create_from_api` -> `send_with_ack_author(.., true)`) and the
    /// `Message::send` wrapper that poll, forward, soft-response and `/roll`
    /// use. The second half fails if `send` stops passing `true`.
    #[test]
    fn self_ack_route_acks_author() {
        crate::util::test::rt().block_on(self_ack_route_acks_author_case())
    }

    async fn self_ack_route_acks_author_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let response = harness
            .client
            .post(format!("/channels/{}/messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .body(json!({ "content": "self ack" }).to_string())
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        let message: v0::Message = response.into_json().await.expect("`Message`");

        // Times out (and fails) after 30s if the send never acked the author.
        let event = harness
            .wait_for_event(&format!("{}!", user.id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &message.id,
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelAck {
                id,
                user: acked_user,
                message_id,
            } => {
                assert_eq!(id, channel.id());
                assert_eq!(acked_user, user.id);
                assert_eq!(message_id, message.id);
            }
            _ => unreachable!(),
        }

        // The `Message::send` wrapper, as poll/forward/soft-response/roll call it.
        let author: v0::User = user.clone().into(&harness.db, Some(&user)).await;
        assert!(author.bot.is_none(), "precondition: the author is a human");

        let mut sent = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: user.id.clone(),
            content: Some("self ack via send".to_string()),
            ..Default::default()
        };

        sent.send(
            &harness.db,
            Some(&harness.amqp),
            v0::MessageAuthor::User(&author),
            Some(author.clone()),
            None,
            &channel,
            false,
        )
        .await
        .expect("Failed to send message");

        // Its own ack: the route's ack above carries a different message id.
        let event = harness
            .wait_for_event(&format!("{}!", user.id), |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &sent.id,
                _ => false,
            })
            .await;

        match event {
            EventV1::ChannelAck {
                id,
                user: acked_user,
                message_id,
            } => {
                assert_eq!(id, channel.id());
                assert_eq!(acked_user, user.id);
                assert_eq!(message_id, sent.id);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn self_ack_skipped_when_opted_out() {
        crate::util::test::rt().block_on(self_ack_skipped_when_opted_out_case())
    }

    async fn self_ack_skipped_when_opted_out_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let author: v0::User = user.clone().into(&harness.db, Some(&user)).await;
        assert!(author.bot.is_none(), "precondition: the author is a human");

        let message = Message::create_from_api_with_id(
            &harness.db,
            Some(&harness.amqp),
            channel.clone(),
            plain_send("opted out"),
            v0::MessageAuthor::User(&author),
            Some(author.clone()),
            None,
            user.limits().await,
            IdempotencyKey::unchecked_from_string("0".to_string()),
            false,
            true,
            None,
            None,
            false,
        )
        .await
        .expect("Failed to create message");

        let marker = flush_with_marker(&mut harness, &user.id, channel.id()).await;
        assert_fanned_out(&mut harness, channel.id(), &message.id).await;

        harness.assert_no_buffered_event(&format!("{}!", user.id), |event| {
            is_stray_ack(event, &marker)
        });
    }

    #[test]
    fn self_ack_skipped_for_webhook() {
        crate::util::test::rt().block_on(self_ack_skipped_for_webhook_case())
    }

    async fn self_ack_skipped_for_webhook_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, user) = harness.new_user().await;
        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;

        let webhook = v0::Webhook {
            id: ulid::Ulid::new().to_string(),
            name: "Self-ack webhook".to_string(),
            avatar: None,
            creator_id: user.id.clone(),
            channel_id: channel.id().to_string(),
            permissions: 0,
            token: None,
        };

        // Same shape as a crosspost copy (message_crosspost.rs).
        let mut message = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: webhook.id.clone(),
            webhook: Some(webhook.clone().into()),
            content: Some("from a webhook".to_string()),
            ..Default::default()
        };

        message
            .send(
                &harness.db,
                Some(&harness.amqp),
                v0::MessageAuthor::Webhook(&webhook),
                None,
                None,
                &channel,
                false,
            )
            .await
            .expect("Failed to send webhook message");

        let marker = flush_with_marker(&mut harness, &user.id, channel.id()).await;
        assert_fanned_out(&mut harness, channel.id(), &message.id).await;

        // Neither the webhook's id nor its creator is acked.
        for topic in [format!("{}!", webhook.id), format!("{}!", user.id)] {
            harness.assert_no_buffered_event(&topic, |event| is_stray_ack(event, &marker));
        }
    }

    #[test]
    fn self_ack_skipped_for_bot() {
        crate::util::test::rt().block_on(self_ack_skipped_for_bot_case())
    }

    async fn self_ack_skipped_for_bot_case() {
        let mut harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (server, _) = harness.new_server(&owner).await;
        let channel = harness.new_channel(&server).await;

        let (_, bot_user) = Bot::create(&harness.db, TestHarness::rand_string(), &owner, None)
            .await
            .expect("`Bot`");
        let (bot_member, _) = Member::create(&harness.db, &server, &bot_user, None)
            .await
            .expect("bot member");

        let author: v0::User = bot_user.clone().into(&harness.db, Some(&owner)).await;
        assert!(
            author.bot.is_some(),
            "precondition: the author carries bot information"
        );

        let mut message = Message {
            id: ulid::Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: bot_user.id.clone(),
            content: Some("from a bot".to_string()),
            ..Default::default()
        };

        // The pinned wrapper (always `ack_author = true`), as bot-driven
        // sends like `/roll` and soft responses reach it.
        message
            .send(
                &harness.db,
                Some(&harness.amqp),
                v0::MessageAuthor::User(&author),
                Some(author.clone()),
                Some(bot_member.into()),
                &channel,
                false,
            )
            .await
            .expect("Failed to send bot message");

        let marker = flush_with_marker(&mut harness, &owner.id, channel.id()).await;
        assert_fanned_out(&mut harness, channel.id(), &message.id).await;

        // Neither the bot nor its owner is acked.
        for topic in [format!("{}!", bot_user.id), format!("{}!", owner.id)] {
            harness.assert_no_buffered_event(&topic, |event| is_stray_ack(event, &marker));
        }
    }

    async fn referral_message_count(harness: &TestHarness, invitee_id: &str) -> i32 {
        harness
            .db
            .fetch_referral(invitee_id)
            .await
            .expect("Failed to fetch referral")
            .expect("Referral is missing")
            .message_count
    }

    /// A pending invitee's accepted sends count towards the referral; notes
    /// to self and rejected sends do not.
    #[test]
    fn referral_activity_recorded_on_send() {
        crate::util::test::rt().block_on(referral_activity_recorded_on_send_case())
    }

    async fn referral_activity_recorded_on_send_case() {
        let harness = TestHarness::new().await;
        let (_, _, referrer) = harness.new_user().await;
        let (_, session, mut user) = harness.new_user().await;

        assert!(Referral::create_for_invitee(
            &harness.db,
            &user.id,
            &referrer.id,
            ReferralSource::Code
        )
        .await
        .expect("Failed to create referral"));
        user.update(
            &harness.db,
            PartialUser {
                referral_pending: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await
        .expect("Failed to mark the referral pending");

        let (server, _) = harness.new_server(&user).await;
        let channel = harness.new_channel(&server).await;
        let notes = Channel::SavedMessages {
            id: ulid::Ulid::new().to_string(),
            user: user.id.clone(),
        };
        harness.db.insert_channel(&notes).await.expect("notes");

        let send = |channel_id: String, body: serde_json::Value| {
            harness
                .client
                .post(format!("/channels/{channel_id}/messages"))
                .header(Header::new("x-session-token", session.token.to_string()))
                .header(ContentType::JSON)
                .body(body.to_string())
                .dispatch()
        };

        let response = send(notes.id().to_string(), json!({ "content": "note" })).await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(referral_message_count(&harness, &user.id).await, 0);

        let response = send(channel.id().to_string(), json!({})).await;
        assert_ne!(response.status(), Status::Ok);
        assert_eq!(referral_message_count(&harness, &user.id).await, 0);

        let response = send(channel.id().to_string(), json!({ "content": "hello" })).await;
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(referral_message_count(&harness, &user.id).await, 1);
    }
}
