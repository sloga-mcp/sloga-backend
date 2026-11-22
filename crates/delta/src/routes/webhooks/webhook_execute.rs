use revolt_config::config;
use revolt_database::{
    util::{e2ee_only, idempotency::IdempotencyKey, reference::Reference},
    Database, Message, AMQP,
};
use revolt_models::v0;
use revolt_permissions::{ChannelPermission, PermissionValue};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};

use validator::Validate;

/// # Executes a webhook
///
/// Executes a webhook and sends a message
#[openapi(tag = "Webhooks")]
#[post("/<webhook_id>/<token>", data = "<data>")]
pub async fn webhook_execute(
    db: &State<Database>,
    amqp: &State<AMQP>,
    webhook_id: Reference<'_>,
    token: String,
    data: Json<v0::DataMessageSend>,
    idempotency: IdempotencyKey,
) -> Result<Json<v0::Message>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let webhook = webhook_id.as_webhook(db).await?;
    webhook.assert_token(&token)?;

    // A webhook can only post plaintext, so a protected channel takes none
    // (design 7.4). Refused after the token check (a caller without it learns
    // nothing about the channel) and before the per-field permission checks,
    // the nonce, attachments and embeds. Keyed on the channel alone: the
    // refusal holds with E2EE or growth off.
    let channel = db.fetch_channel(&webhook.channel_id).await?;
    if channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    // Nor does a group marked encrypted-only, refused at the same point. The
    // files the request named will never be claimed, so they are released
    // at once (a webhook's uploads carry the webhook's id as uploader).
    if let Err(error) =
        e2ee_only::plain_write_allowed_unauthored(&config().await.features.e2ee, &channel)
    {
        let mut named: Vec<String> = data.attachments.clone().unwrap_or_default();
        named.extend(
            data.embeds
                .iter()
                .flatten()
                .filter_map(|embed| embed.media.clone()),
        );
        e2ee_only::release_refused_attachments(db, &webhook.id, &named).await;

        return Err(error);
    }

    let permissions: PermissionValue = webhook.permissions.into();
    permissions.throw_if_lacking_channel_permission(ChannelPermission::SendMessage)?;

    if data.attachments.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::UploadFiles)?;
    }

    if data.embeds.as_ref().is_some_and(|v| !v.is_empty()) {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::SendEmbeds)?;
    }

    if data.masquerade.is_some() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::Masquerade)?;
    }

    if data.interactions.is_some() {
        permissions.throw_if_lacking_channel_permission(ChannelPermission::React)?;
    }

    Ok(Json(
        Message::create_from_api(
            db,
            Some(amqp),
            channel,
            data,
            v0::MessageAuthor::Webhook(&webhook.into()),
            None,
            None,
            config().await.features.limits.default,
            idempotency,
            true,
            true,
        )
        .await?
        .into_model(None, None),
    ))
}

#[cfg(test)]
mod test {
    use crate::util::test::{TestHarness, FIXTURE_DEVICE_CAP, OWNER_DEVICE_SEED};
    use revolt_database::{
        events::client::EventV1, Channel, Database, File, MessageFilter, MessageQuery,
        MessageTimePeriod, Metadata, Webhook,
    };
    use revolt_permissions::ChannelPermission;
    use rocket::http::{ContentType, Status};
    use serde_json::{json, Value};

    struct Fixture {
        harness: TestHarness,
        /// Protected after its webhook was made
        protected: Channel,
        ordinary: Channel,
        protected_hook: Webhook,
        ordinary_hook: Webhook,
    }

    fn webhook(channel: &Channel, creator_id: &str, permissions: u64) -> Webhook {
        Webhook {
            id: ulid::Ulid::new().to_string(),
            name: "Protected test webhook".to_string(),
            avatar: None,
            creator_id: creator_id.to_string(),
            channel_id: channel.id().to_string(),
            permissions,
            token: Some(TestHarness::rand_string()),
        }
    }

    /// Two channels of one owner, each with a webhook of `permissions`; the
    /// first is then protected through the database, so its webhook predates
    /// the protection as a real one would
    async fn fixture(permissions: u64) -> Fixture {
        let harness = TestHarness::new().await;
        let (_, owner_session, owner) = harness.new_user().await;
        let (server, protected) = harness.new_protectable_channel(&owner).await;
        let ordinary = harness.new_channel(&server).await;

        let protected_hook = webhook(&protected, &owner.id, permissions);
        let ordinary_hook = webhook(&ordinary, &owner.id, permissions);
        for hook in [&protected_hook, &ordinary_hook] {
            harness.db.insert_webhook(hook).await.expect("`Webhook`");
        }

        harness
            .grant_entitlement(&protected, crate::util::test::FIXTURE_SLOT_CAP, None)
            .await;
        let owner_device = harness
            .new_e2ee_device(&owner, &owner_session.id, OWNER_DEVICE_SEED)
            .await;
        let protect =
            owner_device.protect_request(protected.id(), FIXTURE_DEVICE_CAP, &[owner.id.clone()]);
        harness.protect_with_db(&protected, &protect).await;
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
        }
    }

    /// POST the body to the webhook; the status and the raw response body
    async fn execute(
        harness: &TestHarness,
        webhook_id: &str,
        token: &str,
        body: &Value,
    ) -> (Status, String) {
        let response = harness
            .client
            .post(format!("/webhooks/{webhook_id}/{token}"))
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

    fn assert_refused(answer: &(Status, String), status: Status, error: &str, case: &str) {
        assert_eq!(answer.0, status, "{case}: {}", answer.1);
        let body: Value = serde_json::from_str(&answer.1).expect("a JSON error body");
        assert_eq!(body["type"], error, "{case}: {}", answer.1);
    }

    async fn stored_messages(harness: &TestHarness, channel: &Channel) -> usize {
        harness
            .db
            .fetch_messages(MessageQuery {
                limit: Some(10),
                filter: MessageFilter {
                    channel: Some(channel.id().to_string()),
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
            .len()
    }

    /// Decision 18 (W2): a protected channel's webhook is refused with
    /// `ChannelProtected`, with no message row, no consumed nonce and no
    /// `Message` event; the same request to an ordinary channel's webhook
    /// still sends
    #[test]
    fn protected_execute_is_refused_without_side_effects() {
        crate::util::test::rt().block_on(Box::pin(
            protected_execute_is_refused_without_side_effects_case(),
        ))
    }

    async fn protected_execute_is_refused_without_side_effects_case() {
        let Fixture {
            mut harness,
            protected,
            ordinary,
            protected_hook,
            ordinary_hook,
        } = fixture(*revolt_permissions::DEFAULT_WEBHOOK_PERMISSIONS).await;

        let nonce = ulid::Ulid::new().to_string();
        let body = json!({ "content": "from a webhook", "nonce": nonce });

        assert_refused(
            &execute(&harness, &protected_hook.id, token(&protected_hook), &body).await,
            Status::BadRequest,
            "ChannelProtected",
            "a protected channel",
        );
        assert_eq!(stored_messages(&harness, &protected).await, 0);

        // Positive control, and the marker for the negative below: the same
        // body (same nonce, so the refusal consumed none) sends, and its
        // `Message` event arrives on the one `psubscribe("*")` connection,
        // FIFO, after anything the refusal could have published
        let (status, sent) =
            execute(&harness, &ordinary_hook.id, token(&ordinary_hook), &body).await;
        assert_eq!(status, Status::Ok, "an ordinary channel: {sent}");
        let sent: Value = serde_json::from_str(&sent).expect("the sent message");
        let sent_id = sent["_id"].as_str().expect("a message id").to_string();
        assert_eq!(stored_messages(&harness, &ordinary).await, 1);

        harness
            .wait_for_event(ordinary.id(), |event| match event {
                EventV1::Message(message) => message.id == sent_id,
                _ => false,
            })
            .await;
        harness
            .assert_no_buffered_event(protected.id(), |event| matches!(event, EventV1::Message(_)));
    }

    /// The refusal runs before the webhook's per-field permission checks: a
    /// webhook that may only send gets `ChannelProtected` in a protected
    /// channel and the pre-W2 `MissingPermission` in an ordinary one
    async fn refused_before_the_field_checks(f: &Fixture) {
        let h = &f.harness;
        for (body, case) in [
            (json!({ "content": "x" }), "plaintext"),
            (
                json!({ "content": "x", "embeds": [{ "title": "x" }] }),
                "embeds",
            ),
            (
                json!({ "content": "x", "masquerade": { "name": "x" } }),
                "a masquerade",
            ),
            (json!({ "attachments": ["x"] }), "attachments"),
        ] {
            assert_refused(
                &execute(h, &f.protected_hook.id, token(&f.protected_hook), &body).await,
                Status::BadRequest,
                "ChannelProtected",
                case,
            );

            let ordinary = execute(h, &f.ordinary_hook.id, token(&f.ordinary_hook), &body).await;
            if case == "plaintext" {
                assert_eq!(ordinary.0, Status::Ok, "{case}: {}", ordinary.1);
            } else {
                assert_refused(&ordinary, Status::Forbidden, "MissingPermission", case);
            }
        }

        assert_eq!(stored_messages(h, &f.protected).await, 0);
    }

    #[test]
    fn protected_execute_is_refused_before_the_field_checks() {
        crate::util::test::rt().block_on(Box::pin(async {
            let f = fixture(ChannelPermission::SendMessage as u64).await;
            refused_before_the_field_checks(&f).await;
        }))
    }

    /// Decision 18 (W2): a bad token gets the pre-W2 answer, byte-identical
    /// for a protected and an ordinary channel's webhook
    #[test]
    fn protected_execute_bad_token_is_answered_as_before() {
        crate::util::test::rt().block_on(Box::pin(async {
            let f = fixture(*revolt_permissions::DEFAULT_WEBHOOK_PERMISSIONS).await;
            let h = &f.harness;

            for (body, case) in [
                (json!({ "content": "x" }), "plaintext"),
                (
                    json!({ "content": "x", "embeds": [{ "title": "x" }] }),
                    "embeds",
                ),
            ] {
                let protected = execute(h, &f.protected_hook.id, "not-the-token", &body).await;
                let ordinary = execute(h, &f.ordinary_hook.id, "not-the-token", &body).await;
                assert_refused(&ordinary, Status::Unauthorized, "NotAuthenticated", case);
                assert_eq!(protected, ordinary, "{case}");
            }

            assert_eq!(stored_messages(h, &f.protected).await, 0);
            assert_eq!(stored_messages(h, &f.ordinary).await, 0);
        }))
    }

    /// The refusal keys on the channel, never on a flag: with E2EE AND
    /// growth off a protected channel's webhook is still refused, first
    #[test]
    fn protected_execute_with_e2ee_and_growth_off_is_refused() {
        crate::util::test::rt().block_on(async {
            // overwrite_config is once-per-process and must run BEFORE the
            // harness primes the config cache; nextest isolates the process
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee_enabled = false;
                settings.features.protected_channels.enabled = false;
            })
            .await;
            let config = revolt_config::config().await;
            assert!(!config.features.e2ee_enabled, "e2ee is off");
            assert!(!config.features.protected_channels.enabled, "growth is off");

            let f = Box::pin(fixture(ChannelPermission::SendMessage as u64)).await;
            Box::pin(refused_before_the_field_checks(&f)).await;
        })
    }

    /// A group of a new owner, stored directly and unmarked, with a webhook
    /// of the default permissions
    async fn group_fixture(harness: &TestHarness) -> (Channel, Webhook) {
        let (_, _, owner) = harness.new_user().await;
        let group = Channel::Group {
            id: ulid::Ulid::new().to_string(),
            name: "Group".to_string(),
            owner: owner.id.clone(),
            description: None,
            recipients: vec![owner.id.clone()],
            icon: None,
            last_message_id: None,
            permissions: None,
            nsfw: false,
            spoiler: false,
            voice: None,
            e2ee_only: false,
        };
        harness.db.insert_channel(&group).await.expect("group");
        let hook = webhook(
            &group,
            &owner.id,
            *revolt_permissions::DEFAULT_WEBHOOK_PERMISSIONS,
        );
        harness.db.insert_webhook(&hook).await.expect("`Webhook`");
        (group, hook)
    }

    /// Set or clear a stored group's encrypted-only mark, raw: no route
    /// writes it after creation
    async fn mark_group_raw(db: &Database, channel_id: &str, marked: bool) {
        match db {
            Database::Reference(reference) => {
                match reference.channels.lock().await.get_mut(channel_id) {
                    Some(Channel::Group { e2ee_only, .. }) => *e2ee_only = marked,
                    other => panic!("expected a group, got {:?}", other),
                }
            }
            Database::MongoDb(mongo) => {
                use revolt_database::mongodb::bson::{doc, Document};

                let result = mongo
                    .col::<Document>("channels")
                    .update_one(
                        doc! { "_id": channel_id },
                        doc! { "$set": { "e2ee_only": marked } },
                    )
                    .await
                    .expect("raw mark");
                assert_eq!(result.matched_count, 1);
            }
        }
    }

    /// An unclaimed message attachment uploaded under `uploader_id`
    async fn unclaimed_attachment(harness: &TestHarness, uploader_id: &str) -> String {
        let id = ulid::Ulid::new().to_string();
        harness
            .db
            .insert_attachment(&File {
                id: id.clone(),
                tag: "attachments".to_string(),
                filename: "file.png".to_string(),
                hash: None,
                uploaded_at: None,
                uploader_id: Some(uploader_id.to_string()),
                used_for: None,
                deleted: None,
                reported: None,
                metadata: Metadata::File,
                content_type: "image/png".to_string(),
                size: 10,
                message_id: None,
                user_id: None,
                server_id: None,
                object_id: None,
            })
            .await
            .expect("attachment");
        id
    }

    /// A group marked encrypted-only refuses the webhook (`group`) before
    /// its field checks: no message row, the named attachment released, the
    /// nonce not consumed (the same nonce sends once the mark is lifted, the
    /// control).
    ///
    /// Control: the `plain_write_allowed_unauthored` call removed → the
    /// refusal turns into the field check's `MissingPermission` (default
    /// webhook permissions carry no UploadFiles).
    #[test]
    fn execute_in_an_encrypted_only_group_is_refused_without_side_effects() {
        crate::util::test::rt().block_on(Box::pin(
            execute_in_an_encrypted_only_group_is_refused_without_side_effects_case(),
        ))
    }

    async fn execute_in_an_encrypted_only_group_is_refused_without_side_effects_case() {
        let harness = TestHarness::new().await;
        let (group, hook) = group_fixture(&harness).await;
        let file_id = unclaimed_attachment(&harness, &hook.id).await;
        let nonce = ulid::Ulid::new().to_string();

        mark_group_raw(&harness.db, group.id(), true).await;
        let refused = execute(
            &harness,
            &hook.id,
            token(&hook),
            &json!({ "content": "from a webhook", "nonce": nonce, "attachments": [file_id] }),
        )
        .await;
        assert_eq!(refused.0, Status::Forbidden, "{}", refused.1);
        let error: Value = serde_json::from_str(&refused.1).expect("a JSON error body");
        assert_eq!(error["type"], "EncryptionRequired", "{}", refused.1);
        assert_eq!(error["side"], "group", "{}", refused.1);
        assert_eq!(stored_messages(&harness, &group).await, 0);

        let released = harness
            .db
            .fetch_deleted_attachments()
            .await
            .expect("deleted attachments");
        assert!(
            released.iter().any(|file| file.id == file_id),
            "the named attachment was not released"
        );

        mark_group_raw(&harness.db, group.id(), false).await;
        let (status, sent) = execute(
            &harness,
            &hook.id,
            token(&hook),
            &json!({ "content": "from a webhook", "nonce": nonce }),
        )
        .await;
        assert_eq!(status, Status::Ok, "an unmarked group: {sent}");
        assert_eq!(stored_messages(&harness, &group).await, 1);
    }

    /// `only_enforced = false` lifts the refusal. Process-wide config, so
    /// nextest only (one process per test).
    #[test]
    fn execute_in_an_encrypted_only_group_is_allowed_when_not_enforced() {
        crate::util::test::rt().block_on(Box::pin(async {
            // Must run before the harness primes the config cache
            revolt_config::overwrite_config(|settings| {
                settings.features.e2ee.only_enforced = false;
            })
            .await;

            let harness = TestHarness::new().await;
            let (group, hook) = group_fixture(&harness).await;
            mark_group_raw(&harness.db, group.id(), true).await;

            let (status, sent) = execute(
                &harness,
                &hook.id,
                token(&hook),
                &json!({ "content": "from a webhook" }),
            )
            .await;
            assert_eq!(status, Status::Ok, "{sent}");
            assert_eq!(stored_messages(&harness, &group).await, 1);
        }))
    }
}
