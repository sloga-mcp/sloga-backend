use revolt_database::{
    util::{permissions::DatabasePermissionQuery, reference::Reference},
    Database, User,
};
use revolt_permissions::{calculate_channel_permissions, ChannelPermission};
use revolt_result::{create_error, Result};
use rocket::State;

/// # Unfollow Announcement Channel
///
/// Severs a follow. Either side may sever it: the source-side admin
/// (`ManageChannel` on the source announcement channel) or the target-side
/// admin (`ManageWebhooks` on the follower channel — who can also just delete
/// the follow's webhook from normal webhook settings).
#[openapi(tag = "Channel Information")]
#[delete("/<source>/follow/<follow_id>")]
pub async fn unfollow_channel(
    db: &State<Database>,
    user: User,
    source: Reference<'_>,
    follow_id: Reference<'_>,
) -> Result<()> {
    let follow = db.fetch_follow(follow_id.id).await?;

    // The follow must actually belong to the source in the path (probe-safe:
    // an unrelated follow id returns NotFound).
    if follow.source_channel != source.id {
        return Err(create_error!(NotFound));
    }

    // Authorize: ManageChannel on the source OR ManageWebhooks on the target.
    let mut authorized = false;

    if let Ok(source_channel) = db.fetch_channel(&follow.source_channel).await {
        let mut query = DatabasePermissionQuery::new(db, &user).channel(&source_channel);
        if calculate_channel_permissions(&mut query)
            .await
            .has_channel_permission(ChannelPermission::ManageChannel)
        {
            authorized = true;
        }
    }

    if !authorized {
        if let Ok(target_channel) = db.fetch_channel(&follow.target_channel).await {
            let mut query = DatabasePermissionQuery::new(db, &user).channel(&target_channel);
            if calculate_channel_permissions(&mut query)
                .await
                .has_channel_permission(ChannelPermission::ManageWebhooks)
            {
                authorized = true;
            }
        }
    }

    if !authorized {
        return Err(create_error!(MissingPermission {
            permission: "ManageChannel".to_string(),
        }));
    }

    // Ordering contract (audit): delete the follow row FIRST + emit, then the
    // webhook — so the `Webhook::delete` follow-sever hook is a no-op here.
    db.delete_channel_follow(&follow.id).await?;
    follow.emit_delete().await;

    if let Ok(webhook) = db.fetch_webhook(&follow.webhook_id).await {
        webhook.delete(db).await.ok();
    }

    Ok(())
}
