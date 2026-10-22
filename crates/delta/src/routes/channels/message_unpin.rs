use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, FieldsMessage, PartialMessage, SystemMessage, User, AMQP,
};
use revolt_models::v0::MessageAuthor;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Unpins a message
///
/// Unpins a message by its id.
#[openapi(tag = "Messaging")]
#[delete("/<target>/messages/<msg>/pin")]
pub async fn message_unpin(
    db: &State<Database>,
    amqp: &State<AMQP>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
) -> Result<EmptyResponse> {
    let channel = target.as_channel(db).await?;

    if !matches!(channel, Channel::DirectMessage { .. }) {
        // Threads inherit their parent channel's permission overrides.
        let permission_channel = channel.permission_target(db).await?.into_owned();
        let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
        calculate_channel_permissions(&mut query)
            .await
            .throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;
    }

    let mut message = msg.as_message_in_channel(db, channel.id()).await?;

    if !message.pinned.unwrap_or_default() {
        return Err(create_error!(NotPinned));
    }

    message
        .update(db, PartialMessage::default(), vec![FieldsMessage::Pinned])
        .await?;

    // A protected channel takes no system rows (decision 16 (W2)): the unpin
    // stands, and its announcement is dropped rather than failing the route
    if channel.is_protected() || message.encrypted.is_some() {
        return Ok(EmptyResponse);
    }

    SystemMessage::MessageUnpinned {
        id: message.id.clone(),
        by: user.id.clone(),
    }
    .into_message(channel.id().to_string())
    .send(
        db,
        Some(amqp),
        MessageAuthor::System {
            username: &user.username,
            avatar: user.avatar.as_ref().map(|file| file.id.as_ref()),
        },
        None,
        None,
        &channel,
        false,
    )
    .await?;

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        events::client::EventV1,
        util::{idempotency::IdempotencyKey, reference::Reference},
        Member, Message, MessageFilter, MessageQuery, MessageTimePeriod, PartialMessage, Server,
        Session,
    };
    use revolt_models::v0::{self, FieldsMessage, SystemMessage};
    use rocket::http::{Header, Status};
    use ulid::Ulid;

    #[test]
    fn unpin_message() {
        crate::util::test::rt().block_on(unpin_message_case())
    }

    async fn unpin_message_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

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

        let channel = &channels[0];

        Member::create(&harness.db, &server, &user, Some(channels.clone()))
            .await
            .expect("Failed to create member");
        let member = Reference::from_unchecked(&user.id)
            .as_member(&harness.db, &server.id)
            .await
            .expect("Failed to get member");

        let message = Message::create_from_api(
            &harness.db,
            None,
            channel.clone(),
            v0::DataMessageSend {
                content: Some("Test message".to_string()),
                nonce: None,
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                encrypted: None,
                flags: None,
            },
            v0::MessageAuthor::User(&user.clone().into(&harness.db, Some(&user)).await),
            Some(user.clone().into(&harness.db, Some(&user)).await),
            Some(member.into()),
            user.limits().await,
            IdempotencyKey::unchecked_from_string("0".to_string()),
            false,
            false,
        )
        .await
        .expect("Failed to create message");

        harness
            .db
            .update_message(
                &message.id,
                &PartialMessage {
                    pinned: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("Failed to update message");

        let response = harness
            .client
            .delete(format!(
                "/channels/{}/messages/{}/pin",
                channel.id(),
                &message.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::NoContent);
        drop(response);

        harness
            .wait_for_event(channel.id(), |event| match event {
                EventV1::Message(message) => match &message.system {
                    Some(SystemMessage::MessageUnpinned { by, .. }) => {
                        assert_eq!(by, &user.id);

                        true
                    }
                    _ => false,
                },
                _ => false,
            })
            .await;

        harness
            .wait_for_event(channel.id(), |event| match event {
                EventV1::MessageUpdate { id, clear, .. } => {
                    assert_eq!(&message.id, id);
                    assert_eq!(clear, &[FieldsMessage::Pinned]);

                    true
                }
                _ => false,
            })
            .await;

        let updated_message = Reference::from_unchecked(&message.id)
            .as_message(&harness.db)
            .await
            .expect("Failed to find updated message");

        assert_eq!(updated_message.pinned, None);
    }

    /// Mark `msg` pinned, raw
    async fn pin_raw(harness: &TestHarness, msg: &str) {
        harness
            .db
            .update_message(
                msg,
                &PartialMessage {
                    pinned: Some(true),
                    ..Default::default()
                },
                vec![],
            )
            .await
            .expect("Failed to pin test message");
    }

    /// The route's full answer: status and body
    async fn unpin(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        msg: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .delete(format!("/channels/{channel_id}/messages/{msg}/pin"))
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    /// Every stored message in `channel_id`
    async fn stored_in(harness: &TestHarness, channel_id: &str) -> Vec<Message> {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel_id.to_string()),
                    ..Default::default()
                },
                time_period: MessageTimePeriod::Absolute {
                    before: None,
                    after: None,
                    sort: None,
                },
            })
            .await
            .expect("the channel's messages")
    }

    #[test]
    fn protected_unpin_sends_no_system_message() {
        crate::util::test::rt().block_on(protected_unpin_sends_no_system_message_case())
    }

    async fn protected_unpin_sends_no_system_message_case() {
        // Decision 16 (W2): the unpin of an encrypted message in a protected
        // channel goes through, but no `MessageUnpinned` row is written or
        // published, and the route answers 204 rather than the floor's refusal
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;

        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let channel_id = protected.channel.id().to_string();
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let message = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;
        pin_raw(&harness, &message.id).await;

        let answer = unpin(&harness, &session, &channel_id, &message.id).await;
        assert_eq!(answer.0, Status::NoContent, "{:?}", answer);

        harness
            .wait_for_event(&channel_id, |event| match event {
                EventV1::MessageUpdate { id, clear, .. } => {
                    id == &message.id && clear == &[FieldsMessage::Pinned]
                }
                _ => false,
            })
            .await;

        // The route awaits its publishes and redis pub/sub is FIFO on the
        // harness's one subscription, so once this marker is seen anything
        // the route published on the channel is in the event buffer
        let marker = Ulid::new().to_string();
        EventV1::ChannelStartTyping {
            id: channel_id.clone(),
            user: marker.clone(),
        }
        .p(channel_id.clone())
        .await;
        harness
            .wait_for_event(&channel_id, |event| match event {
                EventV1::ChannelStartTyping { user, .. } => user == &marker,
                _ => false,
            })
            .await;
        harness.assert_no_buffered_event(
            &channel_id,
            |event| matches!(event, EventV1::Message(message) if message.system.is_some()),
        );

        let stored = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("the unpinned message");
        assert_eq!(stored.pinned, None);
        assert!(stored.encrypted.is_some());

        let rows = stored_in(&harness, &channel_id).await;
        assert_eq!(
            rows.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
            vec![message.id.as_str()],
            "{:?}",
            rows
        );
    }

    #[test]
    fn unprotected_unpin_still_stores_the_system_message() {
        crate::util::test::rt().block_on(unprotected_unpin_still_stores_the_system_message_case())
    }

    async fn unprotected_unpin_still_stores_the_system_message_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;

        let (server, channels) = harness.new_server(&user).await;
        let (channel, _, message) = harness.new_message(&user, &server, channels).await;
        assert!(!channel.is_protected());
        pin_raw(&harness, &message.id).await;

        let answer = unpin(&harness, &session, channel.id(), &message.id).await;
        assert_eq!(answer.0, Status::NoContent, "{:?}", answer);

        let rows = stored_in(&harness, channel.id()).await;
        let unpinned = rows
            .iter()
            .filter(|row| {
                matches!(
                    &row.system,
                    Some(revolt_database::SystemMessage::MessageUnpinned { id, by })
                        if id == &message.id && by == &user.id
                )
            })
            .count();
        assert_eq!(unpinned, 1, "{:?}", rows);
    }

    #[test]
    fn non_moderators_get_the_same_answer_protected_or_not() {
        crate::util::test::rt().block_on(non_moderators_get_the_same_answer_protected_or_not_case())
    }

    async fn non_moderators_get_the_same_answer_protected_or_not_case() {
        // Decision 18 (W2): a caller without ManageMessages gets the pre-W2
        // answer, byte for byte, whatever the channel's protection
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, session, member) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let encrypted = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;
        pin_raw(&harness, &encrypted.id).await;

        let unprotected = harness.new_channel(&protected.server).await;
        let plaintext = Message {
            id: Ulid::new().to_string(),
            channel: unprotected.id().to_string(),
            author: owner.id.clone(),
            content: Some("Test message".to_string()),
            ..Default::default()
        };
        harness
            .db
            .insert_message(&plaintext)
            .await
            .expect("Failed to store test message");
        pin_raw(&harness, &plaintext.id).await;

        let refused = unpin(&harness, &session, protected.channel.id(), &encrypted.id).await;
        let control = unpin(&harness, &session, unprotected.id(), &plaintext.id).await;
        assert_eq!(refused.0, Status::Forbidden, "{:?}", refused);
        let value: serde_json::Value =
            serde_json::from_str(&refused.1).unwrap_or_else(|_| panic!("not JSON: {:?}", refused));
        assert_eq!(value["type"], "MissingPermission", "{}", refused.1);
        assert_eq!(refused, control);

        for id in [&encrypted.id, &plaintext.id] {
            let stored = harness.db.fetch_message(id).await.expect("the message");
            assert_eq!(stored.pinned, Some(true));
        }
    }
}
