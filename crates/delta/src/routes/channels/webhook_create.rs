use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Channel, Database, File, User, Webhook,
};
use revolt_models::v0;
use revolt_permissions::{
    calculate_channel_permissions, ChannelPermission, DEFAULT_WEBHOOK_PERMISSIONS,
};
use revolt_result::{create_error, Result};
use rocket::{serde::json::Json, State};
use ulid::Ulid;
use validator::Validate;

/// # Creates a webhook
///
/// Creates a webhook which 3rd party platforms can use to send messages
#[openapi(tag = "Webhooks")]
#[post("/<channel_id>/webhooks", data = "<data>")]
pub async fn create_webhook(
    db: &State<Database>,
    user: User,
    channel_id: Reference<'_>,
    data: Json<v0::CreateWebhookBody>,
) -> Result<Json<v0::Webhook>> {
    let data = data.into_inner();
    data.validate().map_err(|error| {
        create_error!(FailedValidation {
            error: error.to_string()
        })
    })?;

    let channel = channel_id.as_channel(db).await?;

    if !matches!(channel, Channel::TextChannel { .. } | Channel::Group { .. }) {
        return Err(create_error!(InvalidOperation));
    }

    let mut query = DatabasePermissionQuery::new(db, &user).channel(&channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ManageWebhooks)?;

    // A webhook can only post plaintext, so a protected channel gets none.
    // Refused after the permission check (a caller without it learns nothing
    // about the channel) and before the avatar claim or any write.
    if channel.is_protected() {
        return Err(create_error!(ChannelProtected));
    }

    let webhook_id = Ulid::new().to_string();

    let avatar = match &data.avatar {
        Some(id) => Some(File::use_webhook_avatar(db, id, &webhook_id, &user.id).await?),
        None => None,
    };

    let webhook = Webhook {
        id: webhook_id,
        name: data.name,
        avatar,
        creator_id: user.id,
        channel_id: channel.id().to_string(),
        permissions: *DEFAULT_WEBHOOK_PERMISSIONS,
        token: Some(nanoid::nanoid!(64)),
    };

    webhook.create(db).await?;

    Ok(Json(webhook.into()))
}

#[cfg(test)]
mod test {
    use iso8601_timestamp::Timestamp;
    use revolt_database::{events::client::EventV1, Channel, File, Metadata, User};
    use rocket::http::{ContentType, Header, Status};
    use serde_json::{json, Value};
    use ulid::Ulid;

    use crate::util::test::{ProtectedChannel, TestHarness};

    /// POST a webhook create as the session with `token`. Returns the status
    /// and the JSON body (`Null` when there is none).
    async fn create(
        harness: &TestHarness,
        token: &str,
        channel_id: &str,
        body: &Value,
    ) -> (Status, Value) {
        let response = harness
            .client
            .post(format!("/channels/{channel_id}/webhooks"))
            .header(Header::new("x-session-token", token.to_string()))
            .header(ContentType::JSON)
            .body(body.to_string())
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
        (status, body)
    }

    /// An unclaimed file in the `avatars` bucket, as Autumn leaves an upload
    async fn upload_avatar(harness: &TestHarness, uploader: &User) -> String {
        let id = Ulid::new().to_string();
        harness
            .db
            .insert_attachment(&File {
                id: id.clone(),
                tag: "avatars".to_string(),
                filename: "avatar.png".to_string(),
                hash: None,
                uploaded_at: Some(Timestamp::now_utc()),
                uploader_id: Some(uploader.id.clone()),
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
            .expect("avatar");
        id
    }

    async fn webhook_count(harness: &TestHarness, channel: &Channel) -> usize {
        harness
            .db
            .fetch_webhooks_for_channel(channel.id())
            .await
            .expect("webhooks")
            .len()
    }

    /// The owner's protected channel and an ordinary channel of its server
    async fn fixture(harness: &TestHarness) -> (String, User, ProtectedChannel, Channel) {
        let (_, session, owner) = harness.new_user().await;
        let protected = harness.new_protected_channel(&owner, &session, &[]).await;
        assert!(protected.channel.is_protected());
        let ordinary = harness.new_channel(&protected.server).await;
        (session.token.to_string(), owner, protected, ordinary)
    }

    /// Wait for the `WebhookCreate` of `webhook_id` on `channel_id`
    async fn wait_for_webhook(harness: &mut TestHarness, channel_id: &str, webhook_id: &str) {
        harness
            .wait_for_event(channel_id, |event| match event {
                EventV1::WebhookCreate(webhook) => webhook.id == webhook_id,
                _ => false,
            })
            .await;
    }

    /// A protected channel refuses the create with no side effect: no
    /// webhook row, the avatar left unclaimed, no `WebhookCreate`
    #[test]
    fn protected_webhook_create_is_refused() {
        crate::util::test::rt().block_on(Box::pin(protected_webhook_create_is_refused_case()))
    }

    async fn protected_webhook_create_is_refused_case() {
        let mut harness = TestHarness::new().await;
        let (token, owner, protected, ordinary) = fixture(&harness).await;
        let avatar = upload_avatar(&harness, &owner).await;

        let refused = create(
            &harness,
            &token,
            protected.channel.id(),
            &json!({ "name": "hook", "avatar": avatar }),
        )
        .await;
        assert_eq!(refused.0, Status::BadRequest, "{}", refused.1);
        assert_eq!(refused.1["type"], "ChannelProtected", "{}", refused.1);

        assert_eq!(webhook_count(&harness, &protected.channel).await, 0);
        let file = harness
            .db
            .fetch_attachment("avatars", &avatar)
            .await
            .expect("the avatar");
        assert!(file.used_for.is_none(), "{:?}", file.used_for);

        // Marker: the harness reads every topic through one FIFO
        // subscription, so once this later create's event is seen, any
        // `WebhookCreate` the refused request published is in the buffer
        let marker = create(
            &harness,
            &token,
            ordinary.id(),
            &json!({ "name": "marker" }),
        )
        .await;
        assert_eq!(marker.0, Status::Ok, "{}", marker.1);
        let marker_id = marker.1["id"]
            .as_str()
            .expect("the marker's id")
            .to_string();
        wait_for_webhook(&mut harness, ordinary.id(), &marker_id).await;
        harness.assert_no_buffered_event(protected.channel.id(), |event| {
            matches!(event, EventV1::WebhookCreate(_))
        });
    }

    /// Positive control: the same request on an ordinary channel creates the
    /// webhook, claims the avatar and publishes `WebhookCreate`
    #[test]
    fn unprotected_webhook_create_succeeds() {
        crate::util::test::rt().block_on(Box::pin(unprotected_webhook_create_succeeds_case()))
    }

    async fn unprotected_webhook_create_succeeds_case() {
        let mut harness = TestHarness::new().await;
        let (token, owner, _, ordinary) = fixture(&harness).await;
        let avatar = upload_avatar(&harness, &owner).await;

        let created = create(
            &harness,
            &token,
            ordinary.id(),
            &json!({ "name": "hook", "avatar": avatar }),
        )
        .await;
        assert_eq!(created.0, Status::Ok, "{}", created.1);
        assert_eq!(created.1["channel_id"], ordinary.id(), "{}", created.1);
        let webhook_id = created.1["id"].as_str().expect("the id").to_string();

        assert_eq!(webhook_count(&harness, &ordinary).await, 1);
        let file = harness
            .db
            .fetch_attachment("avatars", &avatar)
            .await
            .expect("the avatar");
        assert_eq!(
            file.used_for.as_ref().map(|used_for| used_for.id.as_str()),
            Some(webhook_id.as_str())
        );
        wait_for_webhook(&mut harness, ordinary.id(), &webhook_id).await;
    }

    /// Decision 18 (W2): a caller without ManageWebhooks (a member, and a
    /// non-member) gets the pre-W2 answer, byte-identical for a protected and
    /// an ordinary channel, and nothing is written
    #[test]
    fn protected_webhook_create_without_permission() {
        crate::util::test::rt()
            .block_on(Box::pin(protected_webhook_create_without_permission_case()))
    }

    async fn protected_webhook_create_without_permission_case() {
        let harness = TestHarness::new().await;
        let (_, _, protected, ordinary) = fixture(&harness).await;
        let (_, member_session, member) = harness.new_user().await;
        harness.join_server(&protected.server, &member).await;
        let (_, outsider_session, _) = harness.new_user().await;

        let body = json!({ "name": "hook" });
        for (session, case) in [
            (&member_session, "a member"),
            (&outsider_session, "a non-member"),
        ] {
            let token = session.token.to_string();
            let refused = create(&harness, &token, protected.channel.id(), &body).await;
            let ordinary_answer = create(&harness, &token, ordinary.id(), &body).await;
            assert_eq!(
                ordinary_answer.0,
                Status::Forbidden,
                "{case}: {}",
                ordinary_answer.1
            );
            assert_eq!(
                ordinary_answer.1["type"], "MissingPermission",
                "{case}: {}",
                ordinary_answer.1
            );
            assert_eq!(refused, ordinary_answer, "{case}");
        }

        assert_eq!(webhook_count(&harness, &protected.channel).await, 0);
        assert_eq!(webhook_count(&harness, &ordinary).await, 0);
    }
}
