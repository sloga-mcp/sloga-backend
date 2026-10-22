use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, PartialMessage, SystemMessage, User, AMQP,
};
use revolt_models::v0::MessageAuthor;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;
use rocket_empty::EmptyResponse;

/// # Pins a message
///
/// Pins a message by its id.
#[openapi(tag = "Messaging")]
#[post("/<target>/messages/<msg>/pin")]
pub async fn message_pin(
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
        let permissions = calculate_channel_permissions(&mut query).await;
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ManageMessages)?;

        // Archived/locked threads reject participation.
        crate::util::threads::ensure_thread_writable(&channel, &permissions)?;
    }

    let mut message = msg.as_message_in_channel(db, channel.id()).await?;

    if message.pinned.unwrap_or_default() {
        return Err(create_error!(AlreadyPinned));
    }

    message
        .update(
            db,
            PartialMessage {
                pinned: Some(true),
                ..Default::default()
            },
            vec![],
        )
        .await?;

    // A protected channel stores no plaintext rows, so the pin stands but
    // its system message is not sent (decision 16): the route still succeeds
    if !channel.is_protected() && message.encrypted.is_none() {
        SystemMessage::MessagePinned {
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
    }

    Ok(EmptyResponse)
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{
        events::client::EventV1,
        util::{idempotency::IdempotencyKey, reference::Reference},
        Channel, Database, Member, Message, MessageFilter, MessageQuery, MessageTimePeriod, Server,
    };
    use revolt_models::v0::{self, SystemMessage};
    use rocket::http::{Header, Status};
    use serde_json::Value;
    use ulid::Ulid;

    #[test]
    fn pin_message() {
        crate::util::test::rt().block_on(pin_message_case())
    }

    async fn pin_message_case() {
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

        let (member, channels) = Member::create(&harness.db, &server, &user, Some(channels))
            .await
            .expect("Failed to create member");
        let channel = &channels[0];

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

        let response = harness
            .client
            .post(format!(
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
                    Some(SystemMessage::MessagePinned { by, .. }) => {
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
                EventV1::MessageUpdate {
                    id,
                    channel: channel_id,
                    data,
                    ..
                } => {
                    assert_eq!(id, &message.id);
                    assert_eq!(channel_id, channel.id());
                    assert_eq!(data.pinned, Some(true));

                    true
                }
                _ => false,
            })
            .await;

        let updated_message = Reference::from_unchecked(&message.id)
            .as_message(&harness.db)
            .await
            .expect("Failed to find updated message");

        assert_eq!(updated_message.pinned, Some(true));
    }

    async fn pin(
        harness: &TestHarness,
        token: &str,
        channel_id: &str,
        id: &str,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/channels/{}/messages/{}/pin", channel_id, id))
            .header(Header::new("x-session-token", token.to_string()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response
            .into_string()
            .await
            .map(|body| serde_json::from_str(&body).unwrap_or(Value::String(body)))
            .unwrap_or(Value::Null);
        (status, body)
    }

    /// Mark `channel_id` protected under its stored plaintext rows, raw, as
    /// the R15 compensation window can leave a stray behind
    async fn protect_under_stored_rows(db: &Database, channel_id: &str) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::TextChannel { protected, .. }) => *protected = true,
                    other => panic!("expected a text channel, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "protected": true } },
                    )
                    .await
                    .expect("raw protect");
                assert_eq!(result.matched_count, 1);
            }
        }

        assert!(db
            .fetch_channel(channel_id)
            .await
            .expect("channel")
            .is_protected());
    }

    /// Pin `id` in `channel_id` and expect the protected outcome: 204, the
    /// `pinned` update stored and published, and no `MessagePinned` system
    /// message, neither as a row nor as a `Message` event on the channel
    async fn assert_pinned_silently(
        harness: &mut TestHarness,
        token: &str,
        channel_id: &str,
        id: &str,
    ) {
        let (status, body) = pin(harness, token, channel_id, id).await;
        assert_eq!(status, Status::NoContent, "{}", body);

        let stored = Reference::from_unchecked(id)
            .as_message(&harness.db)
            .await
            .expect("the pinned message");
        assert_eq!(stored.pinned, Some(true));

        let rows = harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(50),
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
            .expect("the channel's messages");
        assert!(
            rows.iter().all(|row| row.system.is_none()),
            "a system message was stored: {:?}",
            rows
        );

        harness
            .wait_for_event(channel_id, |event| match event {
                EventV1::MessageUpdate {
                    id: updated, data, ..
                } => updated == id && data.pinned == Some(true),
                _ => false,
            })
            .await;

        // Redis pub/sub is FIFO per subscription and the route awaits its
        // publishes: once this later marker is seen, anything the pin
        // published on the channel topic is in the event buffer
        let marker = Ulid::new().to_string();
        EventV1::ChannelAck {
            id: channel_id.to_string(),
            user: marker.clone(),
            message_id: marker.clone(),
        }
        .p(channel_id.to_string())
        .await;
        harness
            .wait_for_event(channel_id, |event| match event {
                EventV1::ChannelAck { message_id, .. } => message_id == &marker,
                _ => false,
            })
            .await;
        harness.assert_no_buffered_event(
            channel_id,
            |event| matches!(event, EventV1::Message(message) if message.system.is_some()),
        );
    }

    /// Decision 16: pinning an encrypted message in a protected channel
    /// succeeds (204) and stores `pinned`, but sends no `MessagePinned`
    /// system message. `pin_message` is the unprotected positive control.
    ///
    /// Control: the system message sent unconditionally (the route at
    /// `db0f44d4`), which the protected insert floor refuses.
    #[test]
    fn protected_pin_sends_no_system_message() {
        crate::util::test::rt().block_on(protected_pin_sends_no_system_message_case())
    }

    async fn protected_pin_sends_no_system_message_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let message = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;

        assert!(protected.channel.is_protected());
        assert!(message.encrypted.is_some());
        assert_pinned_silently(
            &mut harness,
            &session.token,
            protected.channel.id(),
            &message.id,
        )
        .await;
    }

    /// Decision 16 keys on the channel too: a plaintext stray left in a
    /// protected channel (R15) is pinned without a system message.
    ///
    /// Control: as `protected_pin_sends_no_system_message`.
    #[test]
    fn protected_pin_of_a_stray_sends_no_system_message() {
        crate::util::test::rt().block_on(protected_pin_of_a_stray_sends_no_system_message_case())
    }

    async fn protected_pin_of_a_stray_sends_no_system_message_case() {
        let mut harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;
        let (_, channel) = harness.new_protectable_channel(&owner).await;

        let stray = Message {
            id: Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: owner.id.clone(),
            content: Some("Stray".to_string()),
            ..Default::default()
        };
        harness.db.insert_message(&stray).await.expect("message");
        protect_under_stored_rows(&harness.db, channel.id()).await;

        assert_pinned_silently(&mut harness, &session.token, channel.id(), &stray.id).await;
    }

    /// Decision 18: a member without ManageMessages gets the pre-W2 error,
    /// byte-identical for a protected and an unprotected channel, and the
    /// message stays unpinned in both.
    #[test]
    fn pin_without_permission_is_identical_protected_or_not() {
        crate::util::test::rt()
            .block_on(pin_without_permission_is_identical_protected_or_not_case())
    }

    async fn pin_without_permission_is_identical_protected_or_not_case() {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, member_session, member) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[&member])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let sealed = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;

        let (server, open) = harness.new_protectable_channel(&owner).await;
        harness.join_server(&server, &member).await;
        let plain = Message {
            id: Ulid::new().to_string(),
            channel: open.id().to_string(),
            author: owner.id.clone(),
            content: Some("Open".to_string()),
            ..Default::default()
        };
        harness.db.insert_message(&plain).await.expect("message");

        let (protected_status, protected_body) = pin(
            &harness,
            &member_session.token,
            protected.channel.id(),
            &sealed.id,
        )
        .await;
        let (open_status, open_body) =
            pin(&harness, &member_session.token, open.id(), &plain.id).await;

        assert_eq!(open_body["type"], "MissingPermission", "{}", open_body);
        assert_eq!(open_body["permission"], "ManageMessages", "{}", open_body);
        assert_eq!(protected_status, open_status);
        assert_eq!(protected_body, open_body);

        for id in [&sealed.id, &plain.id] {
            let stored = Reference::from_unchecked(id)
                .as_message(&harness.db)
                .await
                .expect("the message");
            assert_eq!(stored.pinned, None, "{}", id);
        }
    }
}
