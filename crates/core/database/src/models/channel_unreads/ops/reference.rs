use revolt_result::Result;
use ulid::Ulid;

use crate::{ChannelCompositeKey, ChannelUnread, ReferenceDb};

use super::AbstractChannelUnreads;

#[async_trait]
impl AbstractChannelUnreads for ReferenceDb {
    /// Acknowledge a message.
    async fn acknowledge_message(
        &self,
        channel_id: &str,
        user_id: &str,
        message_id: &str,
    ) -> Result<Option<ChannelUnread>> {
        // Lock order is channels, then unreads (as in delete_channel). Both are
        // held so a deleted channel can never get an unread row back.
        let channels = self.channels.lock().await;
        let mut unreads = self.channel_unreads.lock().await;
        if !channels.contains_key(channel_id) {
            unreads.retain(|key, _| key.channel != channel_id);
            warn!("Channel {channel_id} is gone; discarded its unread rows");
            return Ok(None);
        }

        let key = ChannelCompositeKey {
            channel: channel_id.to_string(),
            user: user_id.to_string(),
        };

        if let Some(unread) = unreads.get_mut(&key) {
            unread.mentions = None;
            unread.last_id.replace(message_id.to_string());
        } else {
            unreads.insert(
                key.clone(),
                ChannelUnread {
                    id: key.clone(),
                    last_id: Some(message_id.to_string()),
                    mentions: None,
                },
            );
        }

        Ok(unreads.get(&key).cloned())
    }

    /// Acknowledge many channels.
    async fn acknowledge_channels(&self, user_id: &str, channel_ids: &[String]) -> Result<()> {
        let current_time = Ulid::new().to_string();
        for channel_id in channel_ids {
            #[allow(clippy::disallowed_methods)]
            self.acknowledge_message(channel_id, user_id, &current_time)
                .await?;
        }

        Ok(())
    }

    /// Add a mention.
    async fn add_mention_to_unread<'a>(
        &self,
        channel_id: &str,
        user_id: &str,
        message_ids: &[String],
    ) -> Result<()> {
        // Same lock order and deleted-channel check as acknowledge_message.
        let channels = self.channels.lock().await;
        let mut unreads = self.channel_unreads.lock().await;
        if !channels.contains_key(channel_id) {
            unreads.retain(|key, _| key.channel != channel_id);
            warn!("Channel {channel_id} is gone; discarded its unread rows");
            return Ok(());
        }

        let key = ChannelCompositeKey {
            channel: channel_id.to_string(),
            user: user_id.to_string(),
        };

        if let Some(unread) = unreads.get_mut(&key) {
            unread.mentions.replace(message_ids.to_vec());
        } else {
            unreads.insert(
                key.clone(),
                ChannelUnread {
                    id: key,
                    last_id: None,
                    mentions: Some(message_ids.to_vec()),
                },
            );
        }

        Ok(())
    }

    /// Add a mention to multiple users.
    async fn add_mention_to_many_unreads<'a>(
        &self,
        channel_id: &str,
        user_ids: &[String],
        message_ids: &[String],
    ) -> Result<()> {
        // Same lock order and deleted-channel check as acknowledge_message.
        let channels = self.channels.lock().await;
        let mut unreads = self.channel_unreads.lock().await;
        if !channels.contains_key(channel_id) {
            unreads.retain(|key, _| key.channel != channel_id);
            warn!("Channel {channel_id} is gone; discarded its unread rows");
            return Ok(());
        }

        for user_id in user_ids {
            let key = ChannelCompositeKey {
                channel: channel_id.to_string(),
                user: user_id.to_string(),
            };

            if let Some(unread) = unreads.get_mut(&key) {
                unread.mentions.replace(message_ids.to_vec());
            } else {
                unreads.insert(
                    key.clone(),
                    ChannelUnread {
                        id: key,
                        last_id: None,
                        mentions: Some(message_ids.to_vec()),
                    },
                );
            }
        }

        Ok(())
    }

    async fn fetch_unread_mentions(&self, user_id: &str) -> Result<Vec<ChannelUnread>> {
        let unreads = self.channel_unreads.lock().await;
        Ok(unreads
            .values()
            .filter(|unread| unread.id.user == user_id && unread.mentions.is_some())
            .cloned()
            .collect())
    }

    /// Fetch all channel unreads for a user.
    async fn fetch_unreads(&self, user_id: &str) -> Result<Vec<ChannelUnread>> {
        let unreads = self.channel_unreads.lock().await;
        Ok(unreads
            .values()
            .filter(|unread| unread.id.user == user_id)
            .cloned()
            .collect())
    }

    /// Fetch unread for a specific user in a channel.
    async fn fetch_unread(&self, user_id: &str, channel_id: &str) -> Result<Option<ChannelUnread>> {
        let unreads = self.channel_unreads.lock().await;

        Ok(unreads
            .get(&ChannelCompositeKey {
                channel: channel_id.to_string(),
                user: user_id.to_string(),
            })
            .cloned())
    }
}
