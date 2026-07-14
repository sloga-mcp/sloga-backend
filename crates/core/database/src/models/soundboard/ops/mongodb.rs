use revolt_result::Result;

use crate::{MongoDb, PartialSoundboardSound, SoundboardSound};

use super::AbstractSoundboard;

static COL: &str = "sounds";

#[async_trait]
impl AbstractSoundboard for MongoDb {
    async fn insert_soundboard_sound(&self, sound: &SoundboardSound) -> Result<()> {
        query!(self, insert_one, COL, &sound).map(|_| ())
    }

    async fn fetch_soundboard_sound(&self, id: &str) -> Result<SoundboardSound> {
        query!(self, find_one_by_id, COL, id)?.ok_or_else(|| create_error!(NotFound))
    }

    async fn fetch_soundboard_sounds_by_server_id(
        &self,
        server_id: &str,
    ) -> Result<Vec<SoundboardSound>> {
        query!(
            self,
            find,
            COL,
            doc! {
                "server_id": server_id
            }
        )
    }

    async fn fetch_soundboard_sounds_by_server_ids(
        &self,
        server_ids: &[String],
    ) -> Result<Vec<SoundboardSound>> {
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

    async fn update_soundboard_sound(
        &self,
        sound_id: &str,
        partial: &PartialSoundboardSound,
    ) -> Result<()> {
        query!(self, update_one_by_id, COL, sound_id, partial, vec![], None).map(|_| ())
    }

    async fn delete_soundboard_sound(&self, sound_id: &str) -> Result<()> {
        query!(self, delete_one_by_id, COL, sound_id).map(|_| ())
    }
}
