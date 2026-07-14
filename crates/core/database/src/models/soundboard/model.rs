use revolt_models::v0;
use revolt_result::Result;

use crate::events::client::EventV1;
use crate::Database;

auto_derived!(
    /// Soundboard sound — a short per-server audio clip playable in a voice call
    pub struct SoundboardSound {
        /// Unique Id (equals the Autumn file id, like stickers)
        #[serde(rename = "_id")]
        pub id: String,
        /// What server owns this sound
        pub server_id: String,
        /// Uploader user id
        pub creator_id: String,
        /// Sound name
        pub name: String,
        /// File tag this sound is stored under
        pub file_id: String,
        /// Optional emoji shown on the soundboard button
        #[serde(skip_serializing_if = "Option::is_none")]
        pub emoji: Option<String>,
    }

    /// Partial representation of a soundboard sound
    pub struct PartialSoundboardSound {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub emoji: Option<String>,
    }
);

#[allow(clippy::disallowed_methods)]
impl SoundboardSound {
    /// Create a soundboard sound
    pub async fn create(&self, db: &Database) -> Result<()> {
        db.insert_soundboard_sound(self).await?;

        EventV1::SoundboardCreate(self.clone().into())
            .p(self.server_id.clone())
            .await;

        Ok(())
    }

    /// Delete a soundboard sound
    pub async fn delete(self, db: &Database) -> Result<()> {
        EventV1::SoundboardDelete {
            id: self.id.clone(),
        }
        .p(self.server_id.clone())
        .await;

        db.delete_soundboard_sound(&self.id).await
    }

    /// Update a soundboard sound
    pub async fn update(&mut self, db: &Database, partial: PartialSoundboardSound) -> Result<()> {
        if let Some(name) = partial.name.clone() {
            self.name = name;
        }
        if let Some(emoji) = partial.emoji.clone() {
            self.emoji = Some(emoji);
        }

        db.update_soundboard_sound(&self.id, &partial).await?;

        EventV1::SoundboardUpdate {
            id: self.id.clone(),
            data: v0::PartialSoundboardSound {
                name: partial.name.clone(),
                emoji: partial.emoji.clone(),
            },
        }
        .p(self.server_id.clone())
        .await;

        Ok(())
    }
}
