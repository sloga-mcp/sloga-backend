use revolt_result::Result;
use revolt_models::v0;

use crate::events::client::EventV1;
use crate::Database;

auto_derived!(
    /// A follow linking a source announcement channel to a target (follower)
    /// channel. Each follow owns a real webhook in the target channel that
    /// delivers published (crossposted) copies of the source's announcements.
    pub struct ChannelFollow {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// Id of the source announcement channel
        pub source_channel: String,
        /// Id of the server the source channel belongs to
        pub source_server: String,
        /// Id of the target (follower) channel
        pub target_channel: String,
        /// Id of the server the target channel belongs to
        pub target_server: String,
        /// Id of the webhook created in the target channel
        pub webhook_id: String,
        /// Id of the user who created the follow
        pub created_by: String,
        /// When the follow was created (ms since epoch, UTC)
        pub created_at: i64,
    }
);

impl ChannelFollow {
    /// Project into the API model.
    pub fn into_model(self) -> v0::ChannelFollow {
        v0::ChannelFollow {
            id: self.id,
            source_channel: self.source_channel,
            source_server: self.source_server,
            target_channel: self.target_channel,
            target_server: self.target_server,
            webhook_id: self.webhook_id,
            created_by: self.created_by,
            created_at: self.created_at,
        }
    }

    /// Publish the follow-created events: the full follow to the TARGET
    /// server topic, and a privacy-trimmed refetch signal to the SOURCE
    /// server topic (so target ids never leak to non-admin source members).
    ///
    /// Uses the plain `{server}` topic (`.p`) rather than the member topic
    /// (`.server` → `{server}u`) because only BOTS subscribe to `{server}u`
    /// at Ready; regular users subscribe to the plain topic (mirrors how
    /// ChannelUpdate/ChannelCreate reach members).
    pub async fn emit_create(&self) {
        EventV1::ChannelFollowCreate {
            follow: self.clone().into_model(),
        }
        .p(self.target_server.clone())
        .await;

        EventV1::ChannelFollowersUpdate {
            channel: self.source_channel.clone(),
        }
        .p(self.source_server.clone())
        .await;
    }

    /// Publish the follow-deleted events: `ChannelFollowDelete` to the TARGET
    /// server topic and the trimmed `ChannelFollowersUpdate` refetch signal
    /// to the SOURCE server topic. Same plain-`{server}`-topic reasoning as
    /// [`ChannelFollow::emit_create`].
    pub async fn emit_delete(&self) {
        EventV1::ChannelFollowDelete {
            id: self.id.clone(),
            source_channel: self.source_channel.clone(),
            target_channel: self.target_channel.clone(),
        }
        .p(self.target_server.clone())
        .await;

        EventV1::ChannelFollowersUpdate {
            channel: self.source_channel.clone(),
        }
        .p(self.source_server.clone())
        .await;
    }

    /// Cascade cleanup when a channel is deleted — total on both sides so no
    /// orphaned webhook can keep injecting messages.
    ///
    /// Ordering contract (audit): the follow row is deleted FIRST (so the
    /// `Webhook::delete` hook that also severs follows is a no-op on
    /// re-entry), THEN the webhook is removed.
    pub async fn cleanup_for_deleted_channel(db: &Database, channel_id: &str) -> Result<()> {
        // Source side: the deleted channel was an announcement source — drop
        // every follow hanging off it and the webhook each created in its
        // (still-live) target channel, telling the target's webhook settings.
        for follow in db.fetch_follows_by_source(channel_id).await? {
            db.delete_channel_follow(&follow.id).await?;
            if let Ok(webhook) = db.fetch_webhook(&follow.webhook_id).await {
                webhook.delete(db).await.ok();
            }
            follow.emit_delete().await;
        }

        // Target side: the deleted channel was a follower — drop every follow
        // pointing at it AND its now-orphaned webhook document (ordinary
        // channel webhooks are otherwise never reaped on channel delete).
        for follow in db.fetch_follows_by_target(channel_id).await? {
            db.delete_channel_follow(&follow.id).await?;
            db.delete_webhook(&follow.webhook_id).await.ok();
            follow.emit_delete().await;
        }

        Ok(())
    }

    /// Cascade cleanup when a whole server is deleted. The bulk server-delete
    /// path drops the server's channels/webhooks wholesale but never runs
    /// `Channel::delete`, so follows touching the server on EITHER side (and,
    /// crucially, the far-side webhooks that live in *surviving* servers'
    /// channels) would be orphaned. Runs BEFORE the ServerDelete broadcast.
    pub async fn cleanup_for_deleted_server(db: &Database, server_id: &str) -> Result<()> {
        for follow in db.fetch_follows_for_server(server_id).await? {
            db.delete_channel_follow(&follow.id).await?;
            // Remove the injecting webhook wherever it lives — deleting it via
            // Webhook::delete notifies a surviving target channel's webhook
            // settings (and is a no-op event into a dying channel otherwise).
            if let Ok(webhook) = db.fetch_webhook(&follow.webhook_id).await {
                webhook.delete(db).await.ok();
            }
            follow.emit_delete().await;
        }
        Ok(())
    }
}
