use revolt_models::v0;
use revolt_result::Result;

use crate::events::client::EventV1;
use crate::Database;

auto_derived!(
    /// Sticker
    pub struct Sticker {
        /// Unique Id
        #[serde(rename = "_id")]
        pub id: String,
        /// What server owns this sticker
        pub server_id: String,
        /// Uploader user id
        pub creator_id: String,
        /// Sticker name
        pub name: String,
        /// Optional description
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// File tag this sticker is stored under
        pub file_id: String,
        /// Format of the sticker (png, apng, gif, lottie)
        pub format: StickerFormat,
        /// Whether the sticker is marked as nsfw
        #[serde(skip_serializing_if = "crate::if_false", default)]
        pub nsfw: bool,
    }

    /// Format of the sticker
    pub enum StickerFormat {
        PNG,
        APNG,
        GIF,
        Lottie,
    }

    /// Partial representation of a sticker
    pub struct PartialSticker {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nsfw: Option<bool>,
    }
);

#[allow(clippy::disallowed_methods)]
impl Sticker {
    /// Create a sticker
    pub async fn create(&self, db: &Database) -> Result<()> {
        db.insert_sticker(self).await?;

        EventV1::StickerCreate(self.clone().into())
            .p(self.server_id.clone())
            .await;

        Ok(())
    }

    /// Delete a sticker
    pub async fn delete(self, db: &Database) -> Result<()> {
        EventV1::StickerDelete {
            id: self.id.clone(),
        }
        .p(self.server_id.clone())
        .await;

        db.delete_sticker(&self.id).await
    }

    /// Update a sticker
    pub async fn update(&mut self, db: &Database, partial: PartialSticker) -> Result<()> {
        if let Some(name) = partial.name.clone() {
            self.name = name;
        }
        if let Some(description) = partial.description.clone() {
            self.description = Some(description);
        }
        if let Some(nsfw) = partial.nsfw {
            self.nsfw = nsfw;
        }

        db.update_sticker(&self.id, &partial).await?;

        EventV1::StickerUpdate {
            id: self.id.clone(),
            data: v0::PartialSticker {
                name: partial.name.clone(),
                description: partial.description.clone(),
                nsfw: partial.nsfw,
            },
        }
        .p(self.server_id.clone())
        .await;

        Ok(())
    }

}
