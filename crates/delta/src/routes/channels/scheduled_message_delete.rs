use revolt_database::events::client::EventV1;
use revolt_database::util::reference::Reference;
use revolt_database::{Database, User};
use revolt_result::{create_error, Result};
use rocket::State;

/// # Cancel Scheduled Message
///
/// Cancels one of the CALLER'S pending scheduled messages. Author-only:
/// other users get NotFound (pending messages are private, so their
/// existence is never confirmed). A message already claimed by the
/// delivery daemon can no longer be cancelled.
#[openapi(tag = "Messaging")]
#[delete("/<target>/scheduled_messages/<id>")]
pub async fn scheduled_message_delete(
    db: &State<Database>,
    user: User,
    target: Reference<'_>,
    id: Reference<'_>,
) -> Result<()> {
    let row = db.fetch_scheduled_message(id.id).await?;

    // Scope to the addressed channel and to the author. NotFound (not
    // Forbidden) so a non-author can't probe for existence.
    if row.channel != target.id || row.author != user.id {
        return Err(create_error!(NotFound));
    }

    // Loses the race against a claim: once the daemon has the row, the
    // message is effectively sent.
    if !db.delete_scheduled_message_if_pending(&row.id).await? {
        return Err(create_error!(InvalidOperation));
    }

    // Release the attachments claimed at schedule time into the normal
    // deletion sweep.
    if let Some(attachments) = &row.data.attachments {
        if !attachments.is_empty() {
            db.mark_attachments_as_deleted(attachments).await.ok();
        }
    }

    EventV1::MessageScheduleCancelled {
        id: row.id,
        channel: row.channel,
    }
    .private(user.id)
    .await;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::{rocket, util::test::TestHarness};
    use revolt_database::{ScheduledMessage, ScheduledMessageStatus};
    use revolt_models::v0;
    use rocket::http::{Header, Status};

    fn row(id: &str, author: &str, channel: &str) -> ScheduledMessage {
        ScheduledMessage {
            id: id.to_string(),
            author: author.to_string(),
            channel: channel.to_string(),
            server: None,
            scheduled_at: 4_102_444_800_000,
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

    #[rocket::async_test]
    async fn cancel_is_author_only_and_pending_only() {
        let harness = TestHarness::new().await;
        let (_, session, user) = harness.new_user().await;
        let (_, other_session, other_user) = harness.new_user().await;
        let (_server, channels) = harness.new_server(&user).await;
        let channel = &channels[0];

        let pending = row("01CANCEL0000000000000000001", &user.id, channel.id());
        harness
            .db
            .insert_scheduled_message(&pending)
            .await
            .unwrap();

        // Another user cannot cancel it (and cannot learn it exists)
        let _ = other_user;
        let response = harness
            .client
            .delete(format!(
                "/channels/{}/scheduled_messages/{}",
                channel.id(),
                pending.id
            ))
            .header(Header::new(
                "x-session-token",
                other_session.token.to_string(),
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound);

        // The author can
        let response = harness
            .client
            .delete(format!(
                "/channels/{}/scheduled_messages/{}",
                channel.id(),
                pending.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
        assert!(harness
            .db
            .fetch_scheduled_message(&pending.id)
            .await
            .is_err());

        // A claimed row can no longer be cancelled
        let claimed = row("01CANCEL0000000000000000002", &user.id, channel.id());
        harness
            .db
            .insert_scheduled_message(&claimed)
            .await
            .unwrap();
        assert!(harness
            .db
            .claim_scheduled_message(&claimed.id)
            .await
            .unwrap());

        let response = harness
            .client
            .delete(format!(
                "/channels/{}/scheduled_messages/{}",
                channel.id(),
                claimed.id
            ))
            .header(Header::new("x-session-token", session.token.to_string()))
            .dispatch()
            .await;
        assert_ne!(response.status(), Status::Ok);
    }
}
