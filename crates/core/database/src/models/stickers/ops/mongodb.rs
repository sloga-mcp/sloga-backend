use revolt_result::Result;

use crate::{MongoDb, PartialSticker, Sticker};

use super::AbstractStickers;

static COL: &str = "stickers";

#[async_trait]
impl AbstractStickers for MongoDb {
    async fn insert_sticker(&self, sticker: &Sticker) -> Result<()> {
        query!(self, insert_one, COL, &sticker).map(|_| ())
    }

    async fn fetch_sticker(&self, id: &str) -> Result<Sticker> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_stickers_by_server_id(&self, server_id: &str) -> Result<Vec<Sticker>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "server_id": server_id
            }
        )
    }

    async fn fetch_stickers_by_server_ids(&self, server_ids: &[String]) -> Result<Vec<Sticker>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "server_id": {
                    "$in": server_ids
                }
            }
        )
    }

    async fn update_sticker(&self, sticker_id: &str, partial: &PartialSticker) -> Result<()> {
        query!(self, update_one_by_id, COL, sticker_id, partial, vec![], None).map(|_| ())
    }

    async fn delete_sticker(&self, sticker_id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, sticker_id).map(|_| ())
    }
}
