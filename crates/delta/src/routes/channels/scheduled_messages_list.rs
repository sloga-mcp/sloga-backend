use revolt_database::util::permissions::DatabasePermissionQuery;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_models::v0;
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::Result;
use rocket::serde::json::Json;
use rocket::State;

/// # Fetch Scheduled Messages
///
/// Fetches the CALLER'S pending scheduled messages in the given channel,
/// ordered by delivery time. Strictly author-scoped — other users' pending
/// messages are never returned, regardless of permissions.
#[openapi(tag = "Messaging")]
#[get("/<target>/scheduled_messages")]
pub async fn scheduled_messages_list(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
) -> Result<Json<Vec<v0::ScheduledMessage>>> {
    let channel = target.as_channel(db).await?;

    let permission_channel = channel.permission_target(db).await?.into_owned();
    let mut query = DatabasePermissionQuery::new(db, &user).channel(&permission_channel);
    calculate_channel_permissions(&mut query)
        .await
        .throw_if_lacking_channel_permission(ChannelPermission::ViewChannel)?;

    Ok(Json(
        db.fetch_scheduled_messages_by_author(channel.id(), &user.id)
            .await?
            .into_iter()
            .map(|row| row.into_model())
            .collect(),
    ))
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{ScheduledMessage, ScheduledMessageStatus};
    use revolt_models::v0;
    use rocket::http::{ContentType, Header, Status};
    use serde_json::json;

    fn row(id: &str, author: &str, channel: &str) -> ScheduledMessage {
        ScheduledMessage {
            id: id.to_string(),
            author: author.to_string(),
            channel: channel.to_string(),
            server: None,
            scheduled_at: 4_102_444_800_000, // far future
            data: v0::DataMessageSend {
                nonce: None,
                content: Some("pending".to_string()),
                attachments: None,
                replies: None,
                embeds: None,
                masquerade: None,
                interactions: None,
                components: None,
                sticker_ids: None,
                flags: None,
            },
            status: ScheduledMessageStatus::Pending,
            failure_reason: None,
        }
    }

    #[test]
    fn list_is_strictly_author_scoped() {
        crate::util::test::rt().block_on(list_is_strictly_author_scoped_case())
    }

    async fn list_is_strictly_author_scoped_case() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, _, other_user) = harness.new_user().await;
        let (server, channels) = harness.new_server(&user).await;
        let channel = &channels[0];

        harness
            .db
            .insert_scheduled_message(&row(
                "01LISTOWN000000000000000001",
                &user.id,
                channel.id(),
            ))
            .await
            .unwrap();
        // Someone else's pending message in the same channel
        harness
            .db
            .insert_scheduled_message(&row(
                "01LISTOTHER0000000000000001",
                &other_user.id,
                channel.id(),
            ))
            .await
            .unwrap();

        let _ = server;
        let response = harness
            .client
            .get(format!("/channels/{}/scheduled_messages", channel.id()))
            .header(Header::new("x-session-token", session.token.to_string()))
            .header(ContentType::JSON)
            .dispatch()
            .await;

        assert_eq!(response.status(), Status::Ok);
        let rows: Vec<v0::ScheduledMessage> = response.into_json().await.expect("rows");
        assert_eq!(rows.len(), 1, "only the caller's own rows are returned");
        assert_eq!(rows[0].author, user.id);

        // A user without ViewChannel gets nothing at all
        let (_, outsider_session, _) = harness.new_user().await;
        let response = harness
            .client
            .get(format!("/channels/{}/scheduled_messages", channel.id()))
            .header(Header::new(
                "x-session-token",
                outsider_session.token.to_string(),
            ))
            .header(ContentType::JSON)
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);

        let _ = json!({});
    }
}
