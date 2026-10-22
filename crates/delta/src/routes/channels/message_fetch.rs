use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, User,
};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Fetch Message
///
/// Retrieves a message by its id.
#[openapi(tag = "Messaging")]
#[get("/<target>/messages/<msg>")]
pub async fn fetch(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    msg: Reference<'_>,
) -> Result<Json<v0::Message>> {
    let channel = target.as_channel(db).await?;
    // Threads inherit their parent channel's permission overrides.
    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    let permissions = calculate_channel_permissions(&mut query).await;
    permissions.throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    // Thread and forum-post listings hand out every thread's id (which is
    // also its starter message's id) and its last_message_id to anyone with
    // ViewChannel. Fetching those ids here would read history the member was
    // denied, so threads need ReadMessageHistory, as message_query does. A
    // plain channel keeps ViewChannel: ids there only come from messages the
    // member already received live.
    if matches!(channel, Channel::Thread { .. }) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::ReadMessageHistory)?;
    }

    // A protected channel serves only encrypted rows; a stray plaintext row
    // (R15, decision 9 (W2)) answers exactly as a message from another
    // channel does, from this one site
    let message = msg.as_message(db).await?;
    if message.channel != channel.id() || !message.is_servable(channel.is_protected()) {
        return Err(create_error!(NotFound));
    }

    Ok(Json(message.into_model(None, None)))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{Channel, Database, Message, PartialChannel, Session};
    use revolt_permissions::{ChannelPermission, OverrideField};
    use rocket::http::{Header, Status};
    use serde_json::Value;
    use ulid::Ulid;

    /// The route's full answer: status and body
    async fn get(
        harness: &TestHarness,
        session: &Session,
        channel_id: &str,
        message_id: &str,
    ) -> (Status, String) {
        let response = harness
            .client
            .get(format!("/channels/{channel_id}/messages/{message_id}"))
            .header(Header::new("x-session-token", session.token.clone()))
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    #[track_caller]
    fn body(answer: &(Status, String)) -> Value {
        serde_json::from_str(&answer.1).unwrap_or_else(|_| panic!("not JSON: {:?}", answer))
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

    /// A plaintext row by `author` in `channel`, stored through the driver
    async fn insert_plaintext(db: &Database, channel: &Channel, author: &str) -> Message {
        let message = Message {
            id: Ulid::new().to_string(),
            channel: channel.id().to_string(),
            author: author.to_string(),
            content: Some("Test message".to_string()),
            ..Default::default()
        };
        db.insert_message(&message)
            .await
            .expect("Failed to store test plaintext message");
        message
    }

    async fn deny_view(harness: &TestHarness, channel: &Channel) {
        let mut channel = channel.clone();
        channel
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
            .expect("deny view");
    }

    #[test]
    fn stray_in_a_protected_channel_answers_as_a_foreign_message() {
        crate::util::test::rt()
            .block_on(stray_in_a_protected_channel_answers_as_a_foreign_message_case())
    }

    async fn stray_in_a_protected_channel_answers_as_a_foreign_message_case() {
        // R15 backstop, decision 9 (W2): a plaintext row stored in a
        // protected channel is never served, and the miss is byte-identical
        // to asking this channel for a message that lives in another one
        let harness = TestHarness::new().await;
        let (_, session, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, stray) = harness.new_message(&author, &server, channels).await;
        let other = harness.new_channel(&server).await;
        let foreign = insert_plaintext(&harness.db, &other, &author.id).await;

        // Served while the channel is unprotected, so the 404 below is the
        // protection and nothing else
        let before = get(&harness, &session, channel.id(), &stray.id).await;
        assert_eq!(before.0, Status::Ok, "{:?}", before);
        assert_eq!(body(&before)["_id"], stray.id.as_str());

        protect_under_stored_rows(&harness.db, channel.id()).await;

        let stray_answer = get(&harness, &session, channel.id(), &stray.id).await;
        let foreign_answer = get(&harness, &session, channel.id(), &foreign.id).await;

        assert_eq!(stray_answer.0, Status::NotFound, "{:?}", stray_answer);
        let value = body(&stray_answer);
        assert_eq!(value["type"], "NotFound", "{}", stray_answer.1);
        assert!(
            value.get("location").is_none(),
            "the body must not carry the error location: {}",
            stray_answer.1
        );
        assert_eq!(stray_answer, foreign_answer);

        // Dropped from the answer only: the row itself is still stored, so
        // message_delete can remove it
        assert!(harness.db.fetch_message(&stray.id).await.is_ok());
    }

    #[test]
    fn encrypted_message_in_a_protected_channel_is_served() {
        crate::util::test::rt().block_on(encrypted_message_in_a_protected_channel_is_served_case())
    }

    async fn encrypted_message_in_a_protected_channel_is_served_case() {
        let harness = TestHarness::new().await;
        let (_, session, owner) = harness.new_user().await;

        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        assert!(protected.channel.is_protected());
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let message = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;

        let answer = get(&harness, &session, protected.channel.id(), &message.id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(value["_id"], message.id.as_str());
        assert!(value["encrypted"].is_object(), "{}", answer.1);
    }

    #[test]
    fn plaintext_message_in_an_unprotected_channel_is_served() {
        crate::util::test::rt()
            .block_on(plaintext_message_in_an_unprotected_channel_is_served_case())
    }

    async fn plaintext_message_in_an_unprotected_channel_is_served_case() {
        let harness = TestHarness::new().await;
        let (_, session, author) = harness.new_user().await;

        let (server, channels) = harness.new_server(&author).await;
        let (channel, _, message) = harness.new_message(&author, &server, channels).await;
        assert!(!channel.is_protected());

        let answer = get(&harness, &session, channel.id(), &message.id).await;
        assert_eq!(answer.0, Status::Ok, "{:?}", answer);
        let value = body(&answer);
        assert_eq!(value["_id"], message.id.as_str());
        assert_eq!(value["content"], "Test message");
    }

    #[test]
    fn non_viewers_get_the_same_answer_protected_or_not() {
        crate::util::test::rt().block_on(non_viewers_get_the_same_answer_protected_or_not_case())
    }

    async fn non_viewers_get_the_same_answer_protected_or_not_case() {
        // Decision 18 (W2): a caller who cannot view the channel gets the
        // pre-W2 answer, whatever the channel's protection or the row's shape
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (_, session, member) = harness.new_user().await;

        let protected = harness
            .new_protected_channel(&owner, &owner_session, &[])
            .await;
        let group = harness
            .new_text_group(&protected.channel, &protected.owner_device, 0, None)
            .await;
        let encrypted = harness
            .new_encrypted_message(&protected.channel, &protected.owner_device, &group)
            .await;

        let flipped = harness.new_channel(&protected.server).await;
        let stray = insert_plaintext(&harness.db, &flipped, &owner.id).await;
        protect_under_stored_rows(&harness.db, flipped.id()).await;

        let unprotected = harness.new_channel(&protected.server).await;
        let plaintext = insert_plaintext(&harness.db, &unprotected, &owner.id).await;

        harness.join_server(&protected.server, &member).await;

        // A viewer is served the encrypted row and refused the stray, so
        // the non-viewer comparison is with channels that really differ
        let served = get(&harness, &session, protected.channel.id(), &encrypted.id).await;
        assert_eq!(served.0, Status::Ok, "{:?}", served);
        let refused = get(&harness, &session, flipped.id(), &stray.id).await;
        assert_eq!(refused.0, Status::NotFound, "{:?}", refused);
        let open = get(&harness, &session, unprotected.id(), &plaintext.id).await;
        assert_eq!(open.0, Status::Ok, "{:?}", open);

        for channel in [&protected.channel, &flipped, &unprotected] {
            let channel = harness
                .db
                .fetch_channel(channel.id())
                .await
                .expect("the channel");
            deny_view(&harness, &channel).await;
        }

        let baseline = get(&harness, &session, unprotected.id(), &plaintext.id).await;
        assert_eq!(baseline.0, Status::Forbidden, "{:?}", baseline);
        assert_eq!(
            body(&baseline)["type"],
            "MissingPermission",
            "{}",
            baseline.1
        );

        for (case, channel_id, message_id) in [
            ("encrypted", protected.channel.id(), &encrypted.id),
            ("stray", flipped.id(), &stray.id),
        ] {
            let answer = get(&harness, &session, channel_id, message_id).await;
            assert_eq!(answer, baseline, "{}", case);
        }
    }
}
