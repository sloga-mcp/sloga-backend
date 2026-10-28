use iso8601_timestamp::Timestamp;
use revolt_config::config;
use revolt_database::{
    tasks::process_embeds::queue, util::reference::Reference, Database, Message, PartialMessage,
};
use revolt_models::v0::{self, DataEditMessage, Embed};
use revolt_models::validator::Validate;
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

/// # Edits a webhook message
///
/// Edits a message sent by a webhook
#[openapi(tag = "Webhooks")]
#[patch("/<webhook_id>/<token>/<message_id>", data = "<data>")]
pub async fn webhook_edit_message(
    db: &State<Database>,
    webhook_id: Reference<'_>,
    token: String,
    message_id: Reference<'_>,
    data: Json<DataEditMessage>,
) -> Result<Json<v0::Message>> {
    let edit = data.into_inner();
    edit.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    Message::validate_sum(
        &edit.content,
        edit.embeds.as_deref().unwrap_or_default(),
        config().await.features.limits.default.message_length,
    )?;

    let webhook = webhook_id.as_webhook(db).await?;
    webhook.assert_token(&token)?;

    let mut message = message_id.as_message(db).await?;
    if message.author != webhook.id {
        return Err(create_error!(CannotEditMessage));
    }

    // A webhook made before its channel was protected keeps its token, so a
    // protected channel refuses the edit here: after the token and author
    // checks (a bad token learns nothing, decision 18), before any embed,
    // write, event or embed task
    if message.encrypted.is_some() || db.fetch_channel(&message.channel).await?.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    message.edited = Some(Timestamp::now_utc());
    let mut partial = PartialMessage {
        edited: message.edited,
        ..Default::default()
    };

    // 1. Handle content update
    if let Some(content) = &edit.content {
        partial.content = Some(content.clone());
    }

    // 2. Clear any auto generated embeds
    let mut new_embeds = vec![];
    if let Some(embeds) = &message.embeds {
        for embed in embeds {
            if let Embed::Text(embed) = embed {
                new_embeds.push(Embed::Text(embed.clone()))
            }
        }
    }

    // 3. Replace if we are given new embeds
    if let Some(embeds) = edit.embeds {
        new_embeds.clear();

        for embed in embeds {
            new_embeds.push(message.create_embed(db, embed).await?);
        }
    }

    partial.embeds = Some(new_embeds);

    message.update(db, partial, vec![]).await?;

    // Queue up a task for processing embeds
    if let Some(content) = edit.content {
        queue(message.channel.to_string(), message.id.to_string(), content).await;
    }

    Ok(Json(message.into_model(None, None)))
}

#[cfg(test)]
mod test {
    use crate::util::test::TestHarness;
    use revolt_database::{events::client::EventV1, Channel, Database, Message, Webhook};
    use revolt_models::v0::MessageWebhook;
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    struct Fixture {
        harness: TestHarness,
        /// Protected after its webhook posted
        protected: Channel,
        ordinary: Channel,
        protected_hook: Webhook,
        ordinary_hook: Webhook,
        /// The protected webhook's message, a plaintext stray
        protected_message: Message,
        ordinary_message: Message,
    }

    fn webhook(channel: &Channel, creator_id: &str) -> Webhook {
        Webhook {
            id: ulid::Ulid::new().to_string(),
            name: "Protected test webhook".to_string(),
            avatar: None,
            creator_id: creator_id.to_string(),
            channel_id: channel.id().to_string(),
            permissions: *revolt_permissions::DEFAULT_WEBHOOK_PERMISSIONS,
            token: Some(TestHarness::rand_string()),
        }
    }

    /// A plaintext message from `hook` in its channel, stored through the
    /// driver
    async fn insert_webhook_message(db: &Database, hook: &Webhook) -> Message {
        let message = Message {
            id: ulid::Ulid::new().to_string(),
            channel: hook.channel_id.clone(),
            author: hook.id.clone(),
            webhook: Some(MessageWebhook {
                name: hook.name.clone(),
                avatar: None,
            }),
            content: Some("before".to_string()),
            ..Default::default()
        };
        db.insert_message(&message)
            .await
            .expect("Failed to store test webhook message");
        message
    }

    /// Mark `channel_id` protected under its stored plaintext rows, raw, as
    /// the R15 compensation window can leave a stray behind (the protect
    /// primitive refuses a channel with messages)
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
    }

    /// Two channels of one owner, each with a webhook and a message from it;
    /// the first channel is then protected, so its webhook predates the
    /// protection as a real one would
    async fn fixture() -> Fixture {
        let harness = TestHarness::new().await;
        let (_, _, owner) = harness.new_user().await;
        let (server, protected) = harness.new_protectable_channel(&owner).await;
        let ordinary = harness.new_channel(&server).await;

        let protected_hook = webhook(&protected, &owner.id);
        let ordinary_hook = webhook(&ordinary, &owner.id);
        for hook in [&protected_hook, &ordinary_hook] {
            harness.db.insert_webhook(hook).await.expect("`Webhook`");
        }
        let protected_message = insert_webhook_message(&harness.db, &protected_hook).await;
        let ordinary_message = insert_webhook_message(&harness.db, &ordinary_hook).await;

        protect_under_stored_rows(&harness.db, protected.id()).await;
        let protected = harness
            .db
            .fetch_channel(protected.id())
            .await
            .expect("the protected channel");
        assert!(protected.is_protected(), "the fixture channel is protected");

        Fixture {
            harness,
            protected,
            ordinary,
            protected_hook,
            ordinary_hook,
            protected_message,
            ordinary_message,
        }
    }

    /// PATCH the body onto the message through the webhook; the status and
    /// the raw response body
    async fn edit(
        harness: &TestHarness,
        hook: &Webhook,
        token: &str,
        message: &Message,
        body: &Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .patch(format!("/webhooks/{}/{}/{}", hook.id, token, message.id))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        (status, response.into_string().await.unwrap_or_default())
    }

    fn token(hook: &Webhook) -> &str {
        hook.token.as_deref().expect("a webhook token")
    }

    async fn assert_unchanged(harness: &TestHarness, message: &Message) {
        let stored = harness
            .db
            .fetch_message(&message.id)
            .await
            .expect("the stored message");
        assert_eq!(
            stored.content.as_deref(),
            Some("before"),
            "content unchanged"
        );
        assert!(stored.edited.is_none(), "not marked edited");
        assert!(stored.embeds.is_none(), "no embeds written");
    }

    /// Decision 18 (W2): a webhook made before the protect cannot edit its
    /// message in the protected channel: `ChannelProtected`, the row
    /// unchanged and no `MessageUpdate`; the same edit through an ordinary
    /// channel's webhook still applies
    #[test]
    fn protected_webhook_edit_is_refused_without_side_effects() {
        crate::util::test::rt().block_on(Box::pin(
            protected_webhook_edit_is_refused_without_side_effects_case(),
        ))
    }

    async fn protected_webhook_edit_is_refused_without_side_effects_case() {
        let Fixture {
            mut harness,
            protected,
            ordinary,
            protected_hook,
            ordinary_hook,
            protected_message,
            ordinary_message,
        } = fixture().await;

        let body = json!({ "content": "after" });

        let (status, refused) = edit(
            &harness,
            &protected_hook,
            token(&protected_hook),
            &protected_message,
            &body,
        )
        .await;
        assert_eq!(status, Status::BadRequest, "a protected channel: {refused}");
        let refused: Value = serde_json::from_str(&refused).expect("a JSON error body");
        assert_eq!(refused["type"], "ChannelProtected", "{refused}");
        assert_unchanged(&harness, &protected_message).await;

        // Positive control, and the marker for the negative below: its
        // `MessageUpdate` arrives on the one `psubscribe("*")` connection,
        // FIFO, after anything the refusal could have published
        let (status, applied) = edit(
            &harness,
            &ordinary_hook,
            token(&ordinary_hook),
            &ordinary_message,
            &body,
        )
        .await;
        assert_eq!(status, Status::Ok, "an ordinary channel: {applied}");
        let stored = harness
            .db
            .fetch_message(&ordinary_message.id)
            .await
            .expect("the ordinary message");
        assert_eq!(stored.content.as_deref(), Some("after"));

        harness
            .wait_for_event(ordinary.id(), |event| match event {
                EventV1::MessageUpdate { id, .. } => id == &ordinary_message.id,
                _ => false,
            })
            .await;
        harness.assert_no_buffered_event(protected.id(), |event| {
            matches!(event, EventV1::MessageUpdate { .. })
        });
    }

    /// Decision 18 (W2): a bad token gets the pre-W2 error, byte for byte
    /// the same body whether the channel is protected or not
    #[test]
    fn bad_token_error_is_identical_protected_or_not() {
        crate::util::test::rt().block_on(Box::pin(
            bad_token_error_is_identical_protected_or_not_case(),
        ))
    }

    async fn bad_token_error_is_identical_protected_or_not_case() {
        let Fixture {
            harness,
            protected_hook,
            ordinary_hook,
            protected_message,
            ordinary_message,
            ..
        } = fixture().await;

        let body = json!({ "content": "after" });
        let protected = edit(&harness, &protected_hook, "bad", &protected_message, &body).await;
        let ordinary = edit(&harness, &ordinary_hook, "bad", &ordinary_message, &body).await;

        assert_eq!(protected.0, Status::Unauthorized, "{}", protected.1);
        let error: Value = serde_json::from_str(&protected.1).expect("a JSON error body");
        assert_eq!(error["type"], "NotAuthenticated", "{}", protected.1);
        assert_eq!(protected, ordinary, "the bad-token answer reveals nothing");

        assert_unchanged(&harness, &protected_message).await;
        assert_unchanged(&harness, &ordinary_message).await;
    }
}
