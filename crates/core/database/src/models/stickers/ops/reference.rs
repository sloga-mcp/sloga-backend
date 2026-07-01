use revolt_result::Result;

use crate::{PartialSticker, ReferenceDb, Sticker};

use super::AbstractStickers;

#[async_trait]
impl AbstractStickers for ReferenceDb {
    async fn insert_sticker(&self, sticker: &Sticker) -> Result<()> {
        let mut stickers = self.stickers.lock().await;
        if stickers.contains_key(&sticker.id) {
            Err(create_database_error!("insert", "sticker"))
        } else {
            stickers.insert(sticker.id.clone(), sticker.clone());
            Ok(())
        }
    }

    async fn fetch_sticker(&self, id: &str) -> Result<Sticker> {
        let stickers = self.stickers.lock().await;
        stickers
            .get(id)
            .cloned()
            .ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_stickers_by_server_id(&self, server_id: &str) -> Result<Vec<Sticker>> {
        let stickers = self.stickers.lock().await;
        Ok(stickers
            .values()
            .filter(|s| s.server_id == server_id)
            .cloned()
            .collect())
    }

    async fn fetch_stickers_by_server_ids(&self, server_ids: &[String]) -> Result<Vec<Sticker>> {
        let stickers = self.stickers.lock().await;
        Ok(stickers
            .values()
            .filter(|s| server_ids.contains(&s.server_id))
            .cloned()
            .collect())
    }

    async fn update_sticker(&self, sticker_id: &str, partial: &PartialSticker) -> Result<()> {
        let mut stickers = self.stickers.lock().await;
        if let Some(sticker) = stickers.get_mut(sticker_id) {
            if let Some(name) = partial.name.clone() {
                sticker.name = name;
            }
            if let Some(description) = partial.description.clone() {
                sticker.description = Some(description);
            }
            if let Some(nsfw) = partial.nsfw {
                sticker.nsfw = nsfw;
            }
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }

    async fn delete_sticker(&self, sticker_id: &str) -> Result<()> {
        let mut stickers = self.stickers.lock().await;
        if stickers.remove(sticker_id).is_some() {
            Ok(())
        } else {
            Err(create_error!(NotFound))
        }
    }
}
