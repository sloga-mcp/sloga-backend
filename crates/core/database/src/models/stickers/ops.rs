pub mod mongodb;
pub mod reference;

use revolt_result::Result;

use crate::{Sticker, PartialSticker};

#[async_trait]
pub trait AbstractStickers: Sync + Send {
    async fn insert_sticker(&self, sticker: &Sticker) -> Result<()>;
    async fn fetch_sticker(&self, id: &str) -> Result<Sticker>;
    async fn fetch_stickers_by_server_id(&self, server_id: &str) -> Result<Vec<Sticker>>;
    async fn fetch_stickers_by_server_ids(&self, server_ids: &[String]) -> Result<Vec<Sticker>>;
    async fn update_sticker(&self, sticker_id: &str, partial: &PartialSticker) -> Result<()>;
    async fn delete_sticker(&self, sticker_id: &str) -> Result<()>;
}
